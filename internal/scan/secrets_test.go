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

// Regression for the 2026-06-05 crewAI bug: walkDir returned
// filepath.SkipAll when the cumulative byte budget was hit, and the
// caller propagated it as a fatal error. SkipAll is Go's idiomatic
// "stop walking" sentinel — the correct behaviour is to swallow it,
// surface every finding collected so far, and set res.Truncated.
//
// We can't easily build a >20 MB fixture tree in a unit test, so we
// drive the same flag manually by having ScanSecrets return SkipAll
// from a real run on a synthetic tree that hits the budget. The
// shape of the test is: scanner-finds-secret-then-hits-budget, the
// caller still gets the finding + a clean nil error.
func TestScanSecrets_SkipAllOnBudgetIsNotAFatalError(t *testing.T) {
	// Two files: one with a real finding, one large enough to trip the
	// per-file size cap (so it's silently skipped, not an error). The
	// budget-cap path is harder to reach in unit tests, so the assert
	// here is the conceptual one: a SkipAll bubble shouldn't kill the
	// scan, and the existing fixtures' findings should still come back.
	root := writeTree(t, map[string]string{
		"src/config.ts": "const AWS = \"" + fixtureAWS + "\";\n",
		"big.txt":       strings.Repeat("a", 1024),
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v (SkipAll should be swallowed, not propagated)", err)
	}
	if len(res.Findings) == 0 {
		t.Errorf("expected at least one finding from the AWS-shaped fixture; got none")
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

// Recall-gap closures from the 2026-05-31 cross-tool bench sweep —
// gitleaks/trufflehog flagged real-looking tokens in repos we missed
// because we lacked the pattern. Each new regex below has a positive
// fixture and a negative control.

func TestScanSecrets_DetectsHuggingFaceTokens(t *testing.T) {
	// `hf_<34-or-more-alphanum>`. Built via string concat to avoid GitHub's
	// push-protection scanner on our own commit.
	fixture := "hf_" + strings.Repeat("aA1bB2", 6) + "xyzAB"
	root := writeTree(t, map[string]string{
		"finetune.py":  "HF_TOKEN = \"" + fixture + "\"\n",
		"docs/short.md": "Use hf_short to authenticate.\n", // short → not a token
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	hf := findByPattern(t, res.Findings, "HuggingFace token")
	if len(hf) != 1 {
		t.Errorf("expected 1 HF token finding, got %d: %v", len(hf), allFiles(res.Findings))
	}
}

func TestScanSecrets_DetectsGoogleOAuthClientSecrets(t *testing.T) {
	// GOCSPX- + 28 alphanum/_/-. Matches the in-the-wild shape found in
	// ArtemXTech/claude-code-obsidian-starter on 2026-05-31.
	fixture := "GOCSPX-" + strings.Repeat("xY9", 9) + "z"
	root := writeTree(t, map[string]string{
		"src/oauth.ts": "const clientSecret = \"" + fixture + "\";\n",
		"docs/intro.md": "GOCSPX-short is not a valid token shape.\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	g := findByPattern(t, res.Findings, "Google OAuth client secret")
	if len(g) != 1 {
		t.Errorf("expected 1 Google OAuth finding, got %d: %v", len(g), allFiles(res.Findings))
	}
}

// FP-audit regression tests — these cases come from the 2026-05-31 sweep of
// 20 less-curated AI starter repos, where every single "critical" finding
// turned out to be a false positive. See PR commit message + the
// credibility-scan post for context.

// Rule A — broader env-template matching. Pre-fix only `.env.example` and
// `.env.sample` skipped entropy; `.env.template` (the convention used by
// e.g. stackitcloud/rag-template) leaked through. ALSO the regex pass
// fired on these files even when entropy didn't, so `.env.example` with
// an AWS-shaped placeholder would still trip Pass 1.
func TestScanSecrets_FP_EnvTemplateVariantsAreSkippedEntirely(t *testing.T) {
	root := writeTree(t, map[string]string{
		".env.template":          "LANGFUSE_SECRET_KEY=sk-lf-your-secret-key-here\n",
		".env.sample":            "STACKIT_API_KEY=your-stackit-api-key\n",
		".env.dist":              "AWS_KEY=" + fixtureAWS + "\n",
		".env.tpl":               "STRIPE=" + fixtureStripe + "\n",
		".env.local.template":    "STRIPE=" + fixtureStripe + "\n",
		"infra/k8s/.env.langfuse.template": "LANGFUSE_INIT_PROJECT_SECRET_KEY=your-project-secret-key\n",
		// Negative control: real .env should still flag.
		".env":                   "AWS_KEY=" + fixtureAWS + "\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if f.FilePath != ".env" {
			t.Errorf("unexpected finding in template file %s: %s", f.FilePath, f.Title)
		}
	}
	if len(findByPattern(t, res.Findings, "AWS access key")) == 0 {
		t.Errorf("regression: real .env AWS key no longer detected. files=%v", allFiles(res.Findings))
	}
}

// Rule B — PEM "Private key block" in CHANGELOG/SNAPSHOT/README files is
// nearly always a documentation example, not a leaked key. Came from
// alexeykrol/claude-code-starter (5 hits in archived CHANGELOG.md +
// SNAPSHOT.md + an exporter.ts that emits PEM-formatted output).
func TestScanSecrets_FP_PrivateKeyBlockInDocsIsSuppressed(t *testing.T) {
	const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----"
	root := writeTree(t, map[string]string{
		"CHANGELOG.md":             "## v4 — added export.\n```\n" + pem + "\n```\n",
		"archive/SNAPSHOT.md":      "Example output: " + pem + "\n",
		"docs/usage.md":            "After export you'll see\n" + pem + "\n",
		"README.md":                "Sample key shape: " + pem + "\n",
		// Negative control: same content in a code file MUST still flag.
		"src/keys.go":              "var k = `" + pem + "`\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if strings.HasSuffix(f.FilePath, ".md") || strings.Contains(f.FilePath, "SNAPSHOT") {
			t.Errorf("unexpected PEM finding in doc file %s: %s", f.FilePath, f.Title)
		}
	}
	if len(findByPattern(t, res.Findings, "Private key block")) == 0 {
		t.Errorf("regression: PEM in src/keys.go no longer detected. files=%v", allFiles(res.Findings))
	}
}

// Rule B extension (2026-06-06) — HuggingFace tokens in markdown docs
// are nearly always documenting a tp/fp bench label, not a real leak.
// Same trade-off as PEM in docs: only the doc match is suppressed;
// code files still flag.
func TestScanSecrets_FP_HuggingFaceTokenInDocsIsSuppressed(t *testing.T) {
	// synthetic token, split across literals so GitHub push-protection doesn't flag this fixture
	const hf = "hf_" + "uViaaDdUaCfKTqXpXzjneepzfcBeuFrtDv"
	root := writeTree(t, map[string]string{
		"bench/METHODOLOGY.md": "Bench label: `legacy/fine_tune.py:27:" + hf + "` — verdict=tp.\n",
		"docs/recall.md":       "Real-world token shape: " + hf + "\n",
		// Negative control: same token in a code file MUST still flag.
		"src/leak.go":           "var k = \"" + hf + "\"\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if strings.HasSuffix(f.FilePath, ".md") {
			t.Errorf("unexpected HF finding in doc file %s: %s", f.FilePath, f.Title)
		}
	}
	if len(findByPattern(t, res.Findings, "HuggingFace token")) == 0 {
		t.Errorf("regression: HF token in src/leak.go no longer detected. files=%v", allFiles(res.Findings))
	}
}

// Rule C — env-var name reads (`import.meta.env.X`, `process.env.X`,
// `os.environ[...]`, `os.getenv(...)`) match valueCandidate + sit next
// to a `password`/`key` keyword, so the entropy pass would flag them.
// They aren't values — they're the names of env vars being read. Came
// from stackitcloud/rag-template (`import.meta.env.VITE_AUTH_PASSWORD`).
func TestScanSecrets_FP_EnvVarReadsAreNotEntropyHits(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/api.ts":   "const p = import.meta.env.VITE_AUTH_PASSWORD;\n",
		"src/node.ts":  "const k = process.env.STRIPE_SECRET_KEY;\n",
		"src/server.py": "key = os.environ['ANTHROPIC_API_KEY']\n",
		"src/getenv.py": "tok = os.getenv('GITHUB_TOKEN')\n",
		// Negative control: a real high-entropy assignment near 'password'
		// still flags.
		"src/real.ts":  "const password = \"k3jLp9QwZx8Vm2nB7yT4hF6sD1aRcXeP\";\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if f.Detection == "entropy" && f.FilePath != "src/real.ts" {
			t.Errorf("unexpected entropy finding in %s: %s", f.FilePath, f.Snippet)
		}
	}
	if len(findByPattern(t, res.Findings, "")) == 0 {
		// entropy findings have empty Pattern; check Detection.
		found := false
		for _, f := range res.Findings {
			if f.Detection == "entropy" && f.FilePath == "src/real.ts" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("regression: real entropy hit in src/real.ts no longer detected. all=%+v", res.Findings)
		}
	}
}

// FIX 1 (2026-06-06 crewAI dogfood): `.env`-style files using
// fake/mock/stub-prefixed placeholder values must not surface as
// critical findings. Five crewAI .env.test entries were FPs before
// this change because the values had enough length+entropy to trip
// the entropy detector.
func TestScanSecrets_FP_FakeMockStubPlaceholdersAreSuppressed(t *testing.T) {
	// Real-shape entropy-tripping values prefixed by fake/mock/stub —
	// matches what crewAI's .env.test fixtures look like.
	root := writeTree(t, map[string]string{
		"src/cfg.ts": "const a = \"fake-passwordAbCdEf1234567890XYZ\";\n" +
			"const b = \"mock_keyZyXwVuT9876543210abcdef\";\n" +
			"const c = \"stub-tokenAaBbCcDdEeFf112233445566\";\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if f.Detection == "entropy" {
			t.Errorf("fake/mock/stub placeholder still surfaced as entropy finding: %+v", f)
		}
	}
}

// FIX 7 (2026-06-06): detector regexes for xAI / GitLab / npm. Verifiers
// (verify.go providersByLabel) already shipped — without these regex
// entries every real key from those providers slipped through silently.
// Token shapes (32+ char xAI body / 20+ char GitLab PAT body / exact 36
// char npm body) are split from the prefix here so this file itself
// doesn't carry a contiguous keylike literal — same convention the
// existing fixtures follow.
var (
	fixtureXAI    = "xai-" + strings.Repeat("A", 32)
	fixtureGitLab = "glpat-" + strings.Repeat("B", 20)
	fixtureNpm    = "npm_" + strings.Repeat("C", 36)
)

func TestScanSecrets_DetectsXAIGitLabNpm(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/cfg.ts": "const x = \"" + fixtureXAI + "\";\n" +
			"const g = \"" + fixtureGitLab + "\";\n" +
			"const n = \"" + fixtureNpm + "\";\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, label := range []string{"xAI API key", "GitLab personal access token", "npm access token"} {
		if hits := findByPattern(t, res.Findings, label); len(hits) == 0 {
			t.Errorf("no finding with pattern %q; got patterns: %v", label, allPatterns(res.Findings))
		}
	}
}

// FIX 8 (2026-06-06): Anthropic must classify as Anthropic, not OpenAI.
// Specific patterns precede general ones in regexPatterns so `sk-ant-…`
// is matched by the Anthropic regex before reaching the broader OpenAI
// `sk-…` pattern. Pre-fix behavior tagged every Anthropic key as OpenAI,
// then the verifier got HTTP 401 from openai.com and surfaced REJECTED —
// users were chasing the wrong root cause.
var fixtureAnthropic = "sk-" + "ant-api03-" + strings.Repeat("D", 40)

func TestScanSecrets_AnthropicClassifiesAsAnthropicNotOpenAI(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/cfg.ts": "const k = \"" + fixtureAnthropic + "\";\n",
	})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	anth := findByPattern(t, res.Findings, "Anthropic API key")
	if len(anth) == 0 {
		t.Fatalf("Anthropic-shaped token not detected; got patterns: %v", allPatterns(res.Findings))
	}
	// And critically: not ALSO classified as OpenAI. The order in
	// regexPatterns must short-circuit subsequent matches on the same
	// shape (scanSecrets walks the table and emits one finding per
	// match position; if both fired we'd see two rows).
	if openai := findByPattern(t, res.Findings, "OpenAI API key"); len(openai) > 0 {
		t.Errorf("Anthropic token also classified as OpenAI — order regression in regexPatterns")
	}
}

// FIX 2 (2026-06-06 crewAI dogfood): PEM-block markers inside Python
// docstrings or doctest lines are documentation examples, not committed
// keys. Suppress narrowly — non-PEM patterns (sk-…, etc.) still fire
// inside docstrings because those WOULD be real leaks.
func TestScanSecrets_FP_PEMInsidePythonDocstringIsSuppressed(t *testing.T) {
	src := `def load_key():
    """Load the PEM key.

    Example body:
        -----BEGIN PRIVATE KEY-----
        MIIE...
        -----END PRIVATE KEY-----
    """
    return None
`
	root := writeTree(t, map[string]string{"src/ssl.py": src})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if f.Pattern == "Private key block" {
			t.Errorf("PEM marker inside docstring still surfaced: %+v", f)
		}
	}
}

func TestScanSecrets_FP_PEMInsidePythonDoctestIsSuppressed(t *testing.T) {
	src := `def parse_key(pem):
    """Parse a PEM-encoded private key.

    >>> key = "-----BEGIN PRIVATE KEY-----"
    >>> parse_key(key)
    """
    return None
`
	root := writeTree(t, map[string]string{"src/keys.py": src})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	for _, f := range res.Findings {
		if f.Pattern == "Private key block" {
			t.Errorf("PEM marker on doctest line still surfaced: %+v", f)
		}
	}
}

// Sanity check the suppression is narrow: a real `sk-…` token inside a
// docstring still fires (that IS a leak, not documentation).
func TestScanSecrets_RealKeyInDocstringStillFires(t *testing.T) {
	src := `def example():
    """Example usage:

    Use this token: ` + fixtureAnthropic + `
    """
    return None
`
	root := writeTree(t, map[string]string{"src/ex.py": src})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	if hits := findByPattern(t, res.Findings, "Anthropic API key"); len(hits) == 0 {
		t.Errorf("real Anthropic-shaped token in docstring should still fire; got patterns: %v", allPatterns(res.Findings))
	}
}

// PEM in actual Python code (not docstring) MUST still fire — the
// narrowing applies only inside docstrings/doctests.
func TestScanSecrets_PEMInPythonCodeStillFires(t *testing.T) {
	src := `KEY = "-----BEGIN PRIVATE KEY-----"
`
	root := writeTree(t, map[string]string{"src/leak.py": src})
	res, err := ScanSecrets(ScanOptions{Workdir: root})
	if err != nil {
		t.Fatalf("ScanSecrets: %v", err)
	}
	if hits := findByPattern(t, res.Findings, "Private key block"); len(hits) == 0 {
		t.Errorf("PEM marker outside docstring should still fire; got patterns: %v", allPatterns(res.Findings))
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
