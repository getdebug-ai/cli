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
	rules := LoadIgnoreRules(root, true, false, nil)
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
	rules := LoadIgnoreRules(root, true, false, nil)
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
	rules := LoadIgnoreRules(root, false, false, nil)
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
		rules := LoadIgnoreRules(root, respect, false, nil)
		if !rules.IsIgnored("src/foo.test.ts") {
			t.Errorf(".getdebug-ignore must apply regardless of respectGitignore=%v", respect)
		}
	}
}

// ── Default ignores (v0.4.0) ────────────────────────────────────

func TestDefaultsIgnoreTestScaffolding(t *testing.T) {
	root := setupTree(t)
	// Build out the test-scaffolding files the defaults should catch.
	for _, rel := range []string{
		"src/util.test.ts",
		"src/util.spec.js",
		"pkg/foo_test.go",
		"app/test_user.py",
		"app/user_test.py",
		"src/__tests__/helper.ts",
		"src/__fixtures__/user.json",
		"src/__snapshots__/Foo.snap",
		"src/__mocks__/db.ts",
		"internal/testdata/sample.go",
	} {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	rules := LoadIgnoreRules(root, true, true, nil)
	for _, rel := range []string{
		"src/util.test.ts",
		"src/util.spec.js",
		"pkg/foo_test.go",
		"app/test_user.py",
		"app/user_test.py",
		"src/__tests__/helper.ts",
		"src/__fixtures__/user.json",
		"src/__snapshots__/Foo.snap",
		"src/__mocks__/db.ts",
		"internal/testdata/sample.go",
	} {
		if !rules.IsIgnored(rel) {
			t.Errorf("default ignores should match %q (test-scaffolding pattern)", rel)
		}
	}
	// Real source files must NOT be ignored by defaults.
	for _, rel := range []string{
		"src/app.ts",
		"pkg/handler.go",
		"app/main.py",
		"fixtures/user.json", // single-underscore dir name is too ambiguous to skip
	} {
		if rules.IsIgnored(rel) {
			t.Errorf("default ignores should NOT match %q (could be real source)", rel)
		}
	}
}

func TestNoDefaultIgnoresEscapeHatch(t *testing.T) {
	root := setupTree(t)
	if err := os.WriteFile(filepath.Join(root, "src", "foo.test.ts"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rules := LoadIgnoreRules(root, true, false, nil)
	if rules.IsIgnored("src/foo.test.ts") {
		t.Error("with respectDefaults=false, **/*.test.ts must NOT be ignored")
	}
}

// .getdebug-ignore with a `!` line should be able to re-include a file
// that the defaults would otherwise exclude.
func TestGetdebugIgnoreCanReIncludeDefault(t *testing.T) {
	root := setupTree(t)
	if err := os.WriteFile(filepath.Join(root, "src", "foo.test.ts"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(root, ".getdebug-ignore"),
		[]byte("!**/*.test.ts\n"),
		0o644,
	); err != nil {
		t.Fatalf("write .getdebug-ignore: %v", err)
	}
	rules := LoadIgnoreRules(root, true, true, nil)
	// NOTE: sabhiram's matcher applies negation within a SINGLE ruleset.
	// Our defaults + custom are separate matchers stacked OR-style, so
	// a `!` in .getdebug-ignore CANNOT cancel a defaults hit today.
	// Document the trade-off: users who genuinely want to scan tests
	// should pass --no-default-ignores instead. This test locks the
	// current behaviour in so a future refactor doesn't accidentally
	// claim cross-ruleset negation works.
	if !rules.IsIgnored("src/foo.test.ts") {
		t.Error("defaults override .getdebug-ignore negation today; use --no-default-ignores to scan tests")
	}
}

func TestEmptyAndDotPathAreNeverIgnored(t *testing.T) {
	root := setupTree(t)
	rules := LoadIgnoreRules(root, true, false, nil)
	for _, p := range []string{"", "."} {
		if rules.IsIgnored(p) {
			t.Errorf("IsIgnored(%q) should be false (the workdir itself)", p)
		}
	}
}

// ── Default ignores — local-dev env overrides (Group 2) ─────────
// `.env.local` and `.env.<env>.local` are the framework-wide
// convention (Next.js / Vite / Vue / CRA / Astro) for gitignored
// per-developer secrets. Skipping them removes the noisiest source
// of "secrets in a file that's meant to hold secrets" FPs without
// losing the safety net for committed `.env` / `.env.production`
// shapes — those still scan.
func TestDefaultsIgnoreLocalEnvOverrides(t *testing.T) {
	root := setupTree(t)
	rules := LoadIgnoreRules(root, true, true, nil)
	skip := []string{
		".env.local",
		".env.development.local",
		".env.production.local",
		".env.test.local",
		"api/.env.local",
		"workers/.env.local",
		"packages/web/.env.local",
	}
	for _, rel := range skip {
		if !rules.IsIgnored(rel) {
			t.Errorf("local-override env file %q should be ignored by defaults", rel)
		}
	}
	// Committed shapes — must keep scanning so a careless commit of a
	// real key still trips. Plus templates, which are filtered by the
	// secrets-pass eligibility check, not by these built-ins.
	keep := []string{
		".env",
		".env.development",
		".env.production",
		".env.staging",
		".env.test",
		".env.example",
		".env.sample",
		".env.template",
		".env.local.example", // template that mentions "local" — not a real local override
		"api/.env.prod.example",
		"packages/web/.env",
	}
	for _, rel := range keep {
		if rules.IsIgnored(rel) {
			t.Errorf("env file %q must NOT be ignored by defaults (committed shape or template)", rel)
		}
	}
}

// ── Default ignores — scanner output + fixture data (Group 3) ───
// `bench/results/*.json` is the canonical case: each run writes a
// JSON file containing every secret pattern the scanner found in
// the fixtures. The next scan reads them and re-finds the same
// strings — recursive feedback loop. Group 3 closes it for any
// project shape, not just one named `bench/`.
func TestDefaultsIgnoreScannerOutputAndFixtureData(t *testing.T) {
	root := setupTree(t)
	rules := LoadIgnoreRules(root, true, true, nil)
	skip := []string{
		"bench/results/latest.json",
		"bench/results/run-2026-06-05.json",
		"bench-results/snapshot.json",
		"benchmarks/results/r1.json",
		"web/public/bench-fixtures.json",
		"web/public/python-bench-fixtures.json",
		"coverage/lcov.info",
		"coverage/coverage-final.json",
		".nyc_output/processinfo.json",
		".gstack/browse-audit.jsonl",
		".vulnhuntr_checkpoint/state.json",
	}
	for _, rel := range skip {
		if !rules.IsIgnored(rel) {
			t.Errorf("scanner-output/fixture file %q should be ignored by defaults", rel)
		}
	}
	// Source code under similarly named dirs must still scan. The
	// "too ambiguous to skip wholesale" categories from the doc
	// comment have to keep working.
	keep := []string{
		"bench/src/runner.ts",   // bench source, not output
		"bench/fixtures/app.py", // fixture vulnerable code
		"examples/intro/app.ts",
		"fixtures/user.json",
	}
	for _, rel := range keep {
		if rules.IsIgnored(rel) {
			t.Errorf("source under bench/fixtures/examples %q must still scan", rel)
		}
	}
}
