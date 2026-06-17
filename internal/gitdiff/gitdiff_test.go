package gitdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseUnifiedDiff(t *testing.T) {
	diff := `diff --git a/src/a.go b/src/a.go
index 111..222 100644
--- a/src/a.go
+++ b/src/a.go
@@ -1 +1 @@
-old
+new
diff --git a/deleted.txt b/deleted.txt
deleted file mode 100644
--- a/deleted.txt
+++ /dev/null
@@ -1 +0,0 @@
-gone
diff --git a/new file.txt b/new file.txt
new file mode 100644
--- /dev/null
+++ b/new file.txt
@@ -0,0 +1 @@
+hi
`
	got := ParseUnifiedDiff(strings.NewReader(diff))
	sort.Strings(got)
	want := []string{"new file.txt", "src/a.go"} // deleted.txt skipped (post-image /dev/null)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("ParseUnifiedDiff = %v, want %v", got, want)
	}
}

func TestChangedSet_BothSourcesIsError(t *testing.T) {
	if _, err := ChangedSet(t.TempDir(), "HEAD", "some.diff"); err == nil {
		t.Fatal("want error when both --diff-ref and --diff-file are given")
	}
}

func TestChangedSet_NeitherIsNoScope(t *testing.T) {
	set, err := ChangedSet(t.TempDir(), "", "")
	if err != nil || set != nil {
		t.Fatalf("ChangedSet(no args) = (%v, %v), want (nil, nil)", set, err)
	}
}

func TestChangedSet_FromRef(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--initial-branch=main")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("src/a.go", "package a\n")
	write("src/b.go", "package b\n")
	run("add", ".")
	run("commit", "-m", "init")

	// Change only b.go (working tree, vs HEAD).
	write("src/b.go", "package b // changed\n")

	set, err := ChangedSet(dir, "HEAD", "")
	if err != nil {
		t.Fatalf("ChangedSet: %v", err)
	}
	if !set["src/b.go"] {
		t.Fatalf("want src/b.go in changed set, got %v", set)
	}
	if set["src/a.go"] {
		t.Fatalf("did not expect unchanged src/a.go in set, got %v", set)
	}
}
