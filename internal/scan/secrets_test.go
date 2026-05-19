package scan

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Test-fixture tokens. Built via string concatenation so the literal that
// lands in the source file does not match either GitHub's push-protection
// secret scanner or our own detector when scanning this repo. The runtime
// values still match — that's the whole point of the test.
//
// Don't inline a contiguous AWS/GH/Stripe-shaped string anywhere in this
// file. The only tokens the test framework needs are these constants.
var (
	fixtureAWS    = "AKIA" + "IOSFODNN7EXAMPLE"
	fixtureGHPAT  = "ghp_" + strings.Repeat("A", 36)
	fixtureStripe = "sk_live_" + "1234567890abcdefghijklmnop"
	// UUID shape — only flagged by the Heroku detector when "heroku" is on
	// the same line (the regex shape is too broad to flag standalone).
	fixtureHerokuUUID = "12345678-1234-1234-1234" + "-123456789012"
)

// findByPattern returns the findings whose Pattern matches needle. Tests use
// this rather than positional indexing — append-order is an implementation
// detail.
func findByPattern(t *testing.T, fs []Finding, needle string) []Finding {
	t.Helper()
	var out []Finding
	for _, f := range fs {
		if strings.Contains(f.Pattern, needle) {
			out = append(out, f)
		}
	}
	return out
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(abs), err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", abs, err)
		}
	}
	return root
}

func TestScanSecrets_DetectsProviderTokensViaRegex(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/config.ts": "const AWS = \"" + fixtureAWS + "\";\nconst GH = \"" + fixtureGHPAT + "\";\nconst STRIPE = \"" + fixtureStripe + "\";\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	if got, want := res.ScannedFiles, 1; got != want {
		t.Fatalf("ScannedFiles = %d, want %d", got, want)
	}

	for _, label := range []string{"AWS access key", "GitHub PAT", "Stripe secret key"} {
		hits := findByPattern(t, res.Findings, label)
		if len(hits) == 0 {
			t.Errorf("no finding with pattern %q; got patterns: %v", label, allPatterns(res.Findings))
		}
		for _, f := range hits {
			if f.Severity != SeverityCritical {
				t.Errorf("%s: severity = %q, want critical", label, f.Severity)
			}
			if f.Category != "secrets" {
				t.Errorf("%s: category = %q, want secrets", label, f.Category)
			}
			if f.CWE != "CWE-798" {
				t.Errorf("%s: CWE = %q, want CWE-798", label, f.CWE)
			}
		}
	}
}

func TestScanSecrets_EntropyPassFiresOnHighEntropyNearKeyword(t *testing.T) {
	// 32-char base64-ish string near "secret" — should trip the entropy pass.
	const blob = "k3jLp9QwZx8Vm2nB7yT4hF6sD1aRcXeP" // 32 chars, mixed alphabet
	root := writeTree(t, map[string]string{
		"src/app.ts": `const secret = "` + blob + `";` + "\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	var matched *Finding
	for i := range res.Findings {
		if res.Findings[i].Detection == "entropy" {
			matched = &res.Findings[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("expected an entropy-pass finding; got %d findings", len(res.Findings))
	}
	if matched.Severity != SeverityCritical {
		t.Errorf("entropy finding severity = %q, want critical", matched.Severity)
	}
	if !strings.Contains(matched.Snippet, blob[:20]) {
		t.Errorf("snippet does not look like the blob: %q", matched.Snippet)
	}
}

func TestScanSecrets_EntropySkippedInTestsDocsAndEnvExamples(t *testing.T) {
	// Same high-entropy blob, but placed in paths where Pass 2 should not run.
	const blob = "k3jLp9QwZx8Vm2nB7yT4hF6sD1aRcXeP"
	root := writeTree(t, map[string]string{
		"src/app.test.ts":      `const secret = "` + blob + `";` + "\n",
		"docs/intro.md":        "Set the api_key to `" + blob + "` to authenticate.\n",
		".env.example":         "API_KEY=" + blob + "\n",
		"fixtures/keys.ts":     `const token = "` + blob + `";` + "\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if f.Detection == "entropy" {
			t.Errorf("unexpected entropy finding in %s: %+v", f.FilePath, f)
		}
	}
}

func TestScanSecrets_SkipsBuildArtifactsAndLockfiles(t *testing.T) {
	// Lockfile content with what looks like a Stripe key — should NOT be scanned.
	root := writeTree(t, map[string]string{
		"package-lock.json": `{"resolved":"` + fixtureStripe + `"}`,
		"app.tsbuildinfo":   `{"k":"` + fixtureStripe + `"}`,
		"bundle.js.map":     `{"k":"` + fixtureStripe + `"}`,
		// Same content in a regular .ts file → must be detected to prove the
		// negative cases above are about file selection, not the pattern.
		"src/real.ts": `const k = "` + fixtureStripe + `";` + "\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.FilePath, "src/") {
			t.Errorf("finding emitted from filtered file %s: %+v", f.FilePath, f)
		}
	}
	if len(findByPattern(t, res.Findings, "Stripe")) == 0 {
		t.Errorf("real .ts file should have been scanned; got patterns: %v", allPatterns(res.Findings))
	}
}

func TestScanSecrets_SkipsKnownDirs(t *testing.T) {
	root := writeTree(t, map[string]string{
		"node_modules/dep/leak.ts": `const k = "` + fixtureAWS + `";` + "\n",
		".git/hooks/leak":          `const k = "` + fixtureAWS + `";` + "\n",
		"dist/bundle.ts":           `const k = "` + fixtureAWS + `";` + "\n",
		"src/real.ts":              `const k = "` + fixtureAWS + `";` + "\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	if got := len(res.Findings); got != 1 {
		t.Fatalf("findings = %d, want 1 (only src/real.ts); got: %v", got, allFiles(res.Findings))
	}
	if res.Findings[0].FilePath != "src/real.ts" {
		t.Errorf("finding from %s, want src/real.ts", res.Findings[0].FilePath)
	}
}

func TestScanSecrets_PlaceholderValuesAreSuppressed(t *testing.T) {
	// "your_api_key_here" matches placeholder regex → no entropy finding even
	// though the string is long enough.
	root := writeTree(t, map[string]string{
		"src/config.ts": `const api_key = "your_api_key_here_replace_me";` + "\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if f.Detection == "entropy" {
			t.Errorf("placeholder triggered entropy finding: %+v", f)
		}
	}
}

func TestScanSecrets_HerokuRequiresContextWord(t *testing.T) {
	root := writeTree(t, map[string]string{
		// A UUID-shaped string alone is not a finding.
		"src/notes.ts": `const id = "` + fixtureHerokuUUID + `";` + "\n",
		// Same UUID with "heroku" on the line is.
		"src/heroku.ts": `const heroku_key = "` + fixtureHerokuUUID + `";` + "\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	heroku := findByPattern(t, res.Findings, "Heroku")
	if len(heroku) != 1 {
		t.Fatalf("Heroku findings = %d, want exactly 1 (heroku.ts only); files: %v", len(heroku), allFiles(res.Findings))
	}
	if heroku[0].FilePath != "src/heroku.ts" {
		t.Errorf("Heroku finding from %s, want src/heroku.ts", heroku[0].FilePath)
	}
}

func TestScanSecrets_HonorsIgnoreList(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/a.ts": `const k = "` + fixtureAWS + `";` + "\n",
		"src/b.ts": `const k = "` + fixtureAWS + `";` + "\n",
	})
	res, err := ScanSecrets(ScanOptions{
		Workdir: root,
		Ignore:  map[string]struct{}{"src/a.ts": {}},
	})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	if got := len(res.Findings); got != 1 {
		t.Fatalf("findings = %d, want 1 (b.ts only); files: %v", got, allFiles(res.Findings))
	}
	if res.Findings[0].FilePath != "src/b.ts" {
		t.Errorf("finding from %s, want src/b.ts", res.Findings[0].FilePath)
	}
}

func TestScanSecrets_ContentHashIsStableAcrossRuns(t *testing.T) {
	tree := map[string]string{
		"src/a.ts": `const k = "` + fixtureAWS + `";` + "\n",
	}
	root1 := writeTree(t, tree)
	root2 := writeTree(t, tree)
	r1, err := ScanSecrets(ScanOptions{Workdir: root1})
	if err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	r2, err := ScanSecrets(ScanOptions{Workdir: root2})
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if len(r1.Findings) != 1 || len(r2.Findings) != 1 {
		t.Fatalf("expected one finding per run, got %d / %d", len(r1.Findings), len(r2.Findings))
	}
	if r1.Findings[0].ContentHash != r2.Findings[0].ContentHash {
		t.Errorf("content hashes differ across runs (lifecycle persist depends on stability):\n  %s\n  %s",
			r1.Findings[0].ContentHash, r2.Findings[0].ContentHash)
	}
}

// allPatterns + allFiles are test-debug helpers — make error messages useful.
func allPatterns(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Pattern)
	}
	sort.Strings(out)
	return out
}
func allFiles(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.FilePath)
	}
	sort.Strings(out)
	return out
}
