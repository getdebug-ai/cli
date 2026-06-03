package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A missing .getdebug/suppressions.json returns an empty context with no
// log noise — the expected case for any project that hasn't opted in.
func TestLoadSuppressionContextMissingFileIsSilent(t *testing.T) {
	tmp := t.TempDir()
	logged := 0
	ctx := loadSuppressionContext(tmp, func(string, ...any) { logged++ })
	if len(ctx.items) != 0 {
		t.Fatalf("expected empty context, got %d items", len(ctx.items))
	}
	if logged != 0 {
		t.Fatalf("expected no log calls for missing file, got %d", logged)
	}
}

// Malformed JSON is logged and the context is empty — never fail the scan
// over a bad suppressions file.
func TestLoadSuppressionContextMalformedJsonIsLogged(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".getdebug"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".getdebug/suppressions.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs []string
	ctx := loadSuppressionContext(tmp, func(format string, args ...any) {
		logs = append(logs, format)
	})
	if len(ctx.items) != 0 {
		t.Fatalf("expected empty context on malformed JSON, got %d items", len(ctx.items))
	}
	if len(logs) == 0 || !strings.Contains(logs[0], "malformed") {
		t.Fatalf("expected malformed-JSON log, got %v", logs)
	}
}

// Round-trip: a valid file populates the context, the rendered block
// contains the team-policy header and the user's reason verbatim (clipped
// to the cap). Pattern-id and scope render distinctly.
func TestLoadSuppressionContextRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".getdebug"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `[
		{"category":"command-injection","patternId":"exec-with-sandbox","scope":"project","reason":"All exec calls go through sandbox.runSandboxed."},
		{"category":"weak-crypto","patternId":null,"scope":"org","reason":"Hashes here are non-security (cache keys, etagging)."}
	]`
	if err := os.WriteFile(filepath.Join(tmp, ".getdebug/suppressions.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := loadSuppressionContext(tmp, nil)
	if got, want := len(ctx.items), 2; got != want {
		t.Fatalf("items: got %d want %d", got, want)
	}
	block := ctx.renderSuppressionBlock()
	mustContain := []string{
		"TEAM-ACCEPTED PATTERNS",
		"first-party policy",
		"[project]",
		"command-injection / pattern=exec-with-sandbox",
		"sandbox.runSandboxed",
		"[org]",
		"weak-crypto (category-wide)",
		"non-security (cache keys, etagging)",
	}
	for _, s := range mustContain {
		if !strings.Contains(block, s) {
			t.Errorf("rendered block missing %q. block:\n%s", s, block)
		}
	}
}

// Items missing required fields are dropped quietly; unknown scope falls
// back to "project". The model never sees noise that would confuse it.
func TestLoadSuppressionContextNormalisation(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".getdebug"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `[
		{"category":"","patternId":null,"scope":"project","reason":"empty category — dropped"},
		{"category":"xss","patternId":null,"scope":"project","reason":""},
		{"category":"ssrf","patternId":null,"scope":"global","reason":"unknown scope, becomes project"}
	]`
	if err := os.WriteFile(filepath.Join(tmp, ".getdebug/suppressions.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := loadSuppressionContext(tmp, nil)
	if got, want := len(ctx.items), 1; got != want {
		t.Fatalf("after normalisation: got %d items, want %d", got, want)
	}
	if ctx.items[0].Category != "ssrf" || ctx.items[0].Scope != "project" {
		t.Fatalf("unexpected surviving item: %+v", ctx.items[0])
	}
}

// Reasons longer than the cap are clipped before rendering, so one verbose
// entry can't blow the prompt budget on its own.
func TestLoadSuppressionContextReasonCap(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".getdebug"), 0o755); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", maxSuppressionReasonChars+50)
	body := `[{"category":"xss","patternId":null,"scope":"project","reason":"` + long + `"}]`
	if err := os.WriteFile(filepath.Join(tmp, ".getdebug/suppressions.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := loadSuppressionContext(tmp, nil)
	if got := len(ctx.items[0].Reason); got != maxSuppressionReasonChars {
		t.Fatalf("reason cap: got %d chars, want %d", got, maxSuppressionReasonChars)
	}
}

// Items beyond the cap are dropped after sorting — the prompt stays bounded
// even on a project with hundreds of suppressions.
func TestLoadSuppressionContextItemCap(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".getdebug"), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < maxSuppressionPromptItems+5; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		// distinct reasons so dedupe doesn't fold them
		b.WriteString(`{"category":"xss","patternId":null,"scope":"project","reason":"reason-`)
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + (i/26)%26)))
		b.WriteString(`"}`)
	}
	b.WriteString("]")
	if err := os.WriteFile(filepath.Join(tmp, ".getdebug/suppressions.json"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := loadSuppressionContext(tmp, nil)
	if got, want := len(ctx.items), maxSuppressionPromptItems; got != want {
		t.Fatalf("item cap: got %d items, want %d", got, want)
	}
}

// Empty rendered block — callers (sastLocalSystemPrompt) can safely
// concatenate without producing a blank policy header.
func TestRenderSuppressionBlockEmpty(t *testing.T) {
	if got := (suppressionContext{}).renderSuppressionBlock(); got != "" {
		t.Fatalf("empty context should render empty string, got %q", got)
	}
}

// When suppressions are present, the team-policy block lands ABOVE the
// trust boundary in the actual system prompt — verifying the splice point,
// not just the renderer in isolation.
func TestSastLocalSystemPromptSplicesSuppressionsAboveTrustBoundary(t *testing.T) {
	patternID := "exec-with-sandbox"
	ctx := suppressionContext{items: []suppressionContextItem{{
		Category:  "command-injection",
		PatternID: &patternID,
		Scope:     "project",
		Reason:    "Sandboxed.",
	}}}
	prompt := sastLocalSystemPrompt(ctx)
	teamIdx := strings.Index(prompt, "TEAM-ACCEPTED PATTERNS")
	trustIdx := strings.Index(prompt, "CRITICAL — TRUST BOUNDARY")
	if teamIdx < 0 {
		t.Fatal("expected TEAM-ACCEPTED PATTERNS block in prompt")
	}
	if trustIdx < 0 {
		t.Fatal("expected TRUST BOUNDARY block in prompt")
	}
	if teamIdx >= trustIdx {
		t.Fatalf("team policy must come before trust boundary (teamIdx=%d, trustIdx=%d)", teamIdx, trustIdx)
	}
}
