package cmd

import (
	"strings"
	"testing"
)

func TestValidateRepoRelPath_Safe(t *testing.T) {
	cases := []string{
		"src/main.go",
		"foo/bar/baz.ts",
		"a.txt",
		"deeply/nested/dir/with/many/parts/file.py",
		"file-with-dashes.go",
		"file_with_underscores.py",
		"path/with.dots/in.name",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if err := validateRepoRelPath(p); err != nil {
				t.Errorf("validateRepoRelPath(%q) = %v, want nil", p, err)
			}
		})
	}
}

func TestValidateRepoRelPath_Traversal(t *testing.T) {
	// Each of these is the kind of path an attacker would smuggle in via
	// a malicious patch's `+++` line. validateRepoRelPath must reject every
	// shape; if one slips through, the backup loop in applyPatch reads or
	// writes outside the repo root.
	cases := []struct {
		path   string
		reason string
	}{
		{"../etc/passwd", "parent escape"},
		{"../../etc/passwd", "double parent escape"},
		{"../../../../../../etc/shadow", "deep parent escape"},
		{"foo/../../../etc/passwd", "nested parent escape"},
		{"/etc/passwd", "absolute path"},
		{"/", "bare slash"},
		{"/var/run/secrets/token", "absolute path under /var"},
		{"..", "just parent ref"},
		{"./../../etc/passwd", "dot then parent escape"},
		{"foo\\..\\..\\etc\\passwd", "backslash separators"},
		{"C:/Windows/System32/cmd.exe", "windows drive letter"},
		{"D:foo", "drive letter without slash"},
		{"", "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			err := validateRepoRelPath(tc.path)
			if err == nil {
				t.Fatalf("validateRepoRelPath(%q) = nil, want error (%s)", tc.path, tc.reason)
			}
		})
	}
}

func TestFilesFromPatch_RejectsTraversal(t *testing.T) {
	// End-to-end check: the validator is wired into filesFromPatch so a
	// real patch containing a traversal path never reaches applyPatch's
	// backup loop. This is the security-critical assertion.
	patch := `diff --git a/src/foo.go b/src/foo.go
--- a/src/foo.go
+++ b/../../../../etc/passwd
@@ -1,1 +1,1 @@
-old
+new
`
	_, err := filesFromPatch(patch)
	if err == nil {
		t.Fatal("filesFromPatch accepted a traversal path; expected error")
	}
	if !strings.Contains(err.Error(), "unsafe path") {
		t.Errorf("error message = %q, want it to mention 'unsafe path'", err.Error())
	}
}

func TestFilesFromPatch_AcceptsLegitDiff(t *testing.T) {
	patch := `diff --git a/src/foo.go b/src/foo.go
--- a/src/foo.go
+++ b/src/foo.go
@@ -1,1 +1,1 @@
-old
+new
diff --git a/src/bar.go b/src/bar.go
--- a/src/bar.go
+++ b/src/bar.go
@@ -1,1 +1,1 @@
-old
+new
`
	files, err := filesFromPatch(patch)
	if err != nil {
		t.Fatalf("filesFromPatch returned %v on a legit patch", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
	want := map[string]bool{"src/foo.go": true, "src/bar.go": true}
	for _, f := range files {
		if !want[f] {
			t.Errorf("unexpected file in output: %q", f)
		}
	}
}

func TestFilesFromPatch_SkipsDevNull(t *testing.T) {
	// `+++ /dev/null` means a deletion; we don't back up to /dev/null,
	// so skipping it is correct, not an error.
	patch := `--- a/gone.go
+++ /dev/null
@@ -1,1 +0,0 @@
-old
`
	files, err := filesFromPatch(patch)
	if err != nil {
		t.Fatalf("filesFromPatch returned %v", err)
	}
	if len(files) != 0 {
		t.Errorf("got %d files, want 0", len(files))
	}
}

// FIX 16 (2026-06-06 dogfood): every other command accepts "." as the
// workdir alias, so `getdebug fix . --local-only` must too. Pre-fix the
// positional check was a flat rejection of len(args) > 0, which broke
// muscle memory.
func TestValidateFixLocalOnlyArgs(t *testing.T) {
	cases := []struct {
		args    []string
		wantErr bool
		why     string
	}{
		{nil, false, "no positional is the canonical form"},
		{[]string{}, false, "empty slice == no positional"},
		{[]string{"."}, false, "workdir alias accepted (FIX 16)"},
		{[]string{"./"}, false, "trailing slash still cleans to '.'"},
		{[]string{"./."}, false, "redundant slash+dot still cleans to '.'"},
		{[]string{"fix_abc123"}, true, "a real fix-id positional is nonsensical with --local-only"},
		{[]string{"src/foo.go"}, true, "a file path is not a workdir alias"},
		{[]string{".."}, true, "parent dir is not the current workdir"},
	}
	for _, tc := range cases {
		err := validateFixLocalOnlyArgs(tc.args)
		gotErr := err != nil
		if gotErr != tc.wantErr {
			t.Errorf("validateFixLocalOnlyArgs(%v) gotErr=%v want=%v (%s)", tc.args, gotErr, tc.wantErr, tc.why)
		}
	}
}
