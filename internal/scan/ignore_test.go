package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// build a temp workdir with a few files + nested .gitignore. The
// tests use this to verify both root + nested .gitignore semantics
// and the .getdebug-ignore overlay.
func setupTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, content string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	mk(".gitignore", "*.log\nbuild/\nsecret.txt\n")
	mk("bench/.gitignore", "results/\n")
	mk("src/app.ts", "//src")
	mk("src/app.log", "//log")
	mk("build/out.js", "//build")
	mk("secret.txt", "shh")
	mk("bench/run.ts", "//bench")
	mk("bench/results/run-1.json", "{}")
	return root
}

func TestIgnoreRulesetRespectsRootGitignore(t *testing.T) {
	root := setupTree(t)
	rules := LoadIgnoreRules(root, true, nil)
	cases := map[string]bool{
		"src/app.ts":   false,
		"src/app.log":  true,
		"build/out.js": true,
		"secret.txt":   true,
		"bench/run.ts": false,
	}
	for p, want := range cases {
		if got := rules.IsIgnored(p); got != want {
			t.Errorf("IsIgnored(%q) = %v want %v", p, got, want)
		}
	}
}

// The "results/" rule lives in bench/.gitignore, scoped to bench/.
// Without nested .gitignore support this test would fail — same gap
// that let bench/results/*.json explode the user's self-scan.
func TestIgnoreRulesetHonoursNestedGitignore(t *testing.T) {
	root := setupTree(t)
	rules := LoadIgnoreRules(root, true, nil)
	if !rules.IsIgnored("bench/results/run-1.json") {
		t.Error("bench/results/run-1.json should be ignored via bench/.gitignore")
	}
	if !rules.IsDirIgnored("bench/results") {
		t.Error("bench/results should be dir-ignored")
	}
	if rules.IsIgnored("bench/run.ts") {
		t.Error("bench/run.ts (sibling of results/) should NOT be ignored")
	}
}

func TestNoGitignoreSkipsTheLayer(t *testing.T) {
	root := setupTree(t)
	rules := LoadIgnoreRules(root, false, nil)
	if rules.IsIgnored("src/app.log") {
		t.Error("with respectGitignore=false, *.log must NOT be ignored")
	}
	if rules.IsIgnored("bench/results/run-1.json") {
		t.Error("with respectGitignore=false, nested rules must NOT apply either")
	}
}

func TestGetdebugIgnoreAppliesAlways(t *testing.T) {
	root := setupTree(t)
	if err := os.WriteFile(
		filepath.Join(root, ".getdebug-ignore"),
		[]byte("**/*.test.ts\n"),
		0o644,
	); err != nil {
		t.Fatalf("write .getdebug-ignore: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "foo.test.ts"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	for _, respect := range []bool{true, false} {
		rules := LoadIgnoreRules(root, respect, nil)
		if !rules.IsIgnored("src/foo.test.ts") {
			t.Errorf(".getdebug-ignore must apply regardless of respectGitignore=%v", respect)
		}
	}
}

func TestEmptyAndDotPathAreNeverIgnored(t *testing.T) {
	root := setupTree(t)
	rules := LoadIgnoreRules(root, true, nil)
	for _, p := range []string{"", "."} {
		if rules.IsIgnored(p) {
			t.Errorf("IsIgnored(%q) should be false (the workdir itself)", p)
		}
	}
}
