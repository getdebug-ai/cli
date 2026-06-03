package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── client-side-llm-key prefilter ────────────────────────────────

func TestClientSideLlmKeyDetectsNextPublicOpenAI(t *testing.T) {
	src := `const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;`
	hits := scanClientSideLlmKey("src/k.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	h := hits[0]
	if h.Category != "client-side-llm-key" {
		t.Errorf("category=%q want client-side-llm-key", h.Category)
	}
	if h.Severity != SeverityCritical {
		t.Errorf("severity=%q want critical", h.Severity)
	}
	if h.LineStart != 1 {
		t.Errorf("lineStart=%d want 1", h.LineStart)
	}
	if h.CWE != "CWE-798" {
		t.Errorf("cwe=%q want CWE-798", h.CWE)
	}
	if h.Detection != "regex" {
		t.Errorf("detection=%q want regex", h.Detection)
	}
}

func TestClientSideLlmKeyDetectsViteAnthropic(t *testing.T) {
	src := `const k = import.meta.env.VITE_ANTHROPIC_API_KEY;`
	hits := scanClientSideLlmKey("k.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for VITE_ANTHROPIC_API_KEY, got %d", len(hits))
	}
}

func TestClientSideLlmKeyDetectsExpoPublic(t *testing.T) {
	src := `const k = process.env.EXPO_PUBLIC_GROQ_KEY;`
	hits := scanClientSideLlmKey("k.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for EXPO_PUBLIC_GROQ_KEY, got %d", len(hits))
	}
}

// Doc comments and changelog mentions of the same var name must NOT
// fire — this was the self-scan FP the hosted side learned about.
func TestClientSideLlmKeySkipsCommentLines(t *testing.T) {
	src := `// process.env.NEXT_PUBLIC_OPENAI_API_KEY is dangerous; do not do this.
const k = "ok";`
	hits := scanClientSideLlmKey("doc.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits in comment, got %d: %+v", len(hits), hits)
	}
}

// A var with a public-prefix but a NON-LLM provider name must not
// match — the hosted regex narrows by provider list specifically to
// avoid PUBLIC_DB_URL etc.
func TestClientSideLlmKeyIgnoresNonLlmProviderNames(t *testing.T) {
	src := `const k = process.env.NEXT_PUBLIC_DATABASE_URL;`
	hits := scanClientSideLlmKey("k.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits for non-LLM provider var, got %d", len(hits))
	}
}

// A var WITHOUT a recognized public prefix must not fire (server-side
// key is fine; the pattern is about client-bundle exposure).
func TestClientSideLlmKeyIgnoresServerOnlyName(t *testing.T) {
	src := `const k = process.env.OPENAI_API_KEY;`
	hits := scanClientSideLlmKey("k.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits for server-only OPENAI_API_KEY, got %d", len(hits))
	}
}

// ── unbounded-stream prefilter ───────────────────────────────────

func TestUnboundedStreamDetectsBareStreamTrue(t *testing.T) {
	src := `const r = await openai.chat.completions.create({
  model: "gpt-4",
  stream: true,
});`
	hits := scanUnboundedStream("s.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	h := hits[0]
	if h.Category != "unbounded-stream" {
		t.Errorf("category=%q want unbounded-stream", h.Category)
	}
	if h.Severity != SeverityMedium {
		t.Errorf("severity=%q want medium", h.Severity)
	}
	if h.LineStart != 3 {
		t.Errorf("lineStart=%d want 3", h.LineStart)
	}
	if h.CWE != "CWE-770" {
		t.Errorf("cwe=%q want CWE-770", h.CWE)
	}
}

// Web Streams API false positive — the most common one per the hosted
// post-mortem. Must NEVER fire on decoder.decode({ stream: true }).
func TestUnboundedStreamSkipsTextDecoderShape(t *testing.T) {
	src := `const out = decoder.decode(chunk, { stream: true });`
	hits := scanUnboundedStream("sse.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits for TextDecoder, got %d", len(hits))
	}
}

// stream: true on its own line, but an AbortController declared
// earlier — the stream IS bounded. Skip.
func TestUnboundedStreamSkipsWhenAbortControllerNearby(t *testing.T) {
	src := `const controller = new AbortController();
const r = await openai.chat.completions.create({
  model: "gpt-4",
  stream: true,
  signal: controller.signal,
});`
	hits := scanUnboundedStream("s.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits with AbortController nearby, got %d", len(hits))
	}
}

// Comments and start-of-string-literal matches must not fire — common
// in docs that explain the WRONG pattern as a teaching example. The
// helper matches the hosted inNonCodeContext shape: it catches the
// "// …" line case and the "<quote><match>…" immediately-after-quote
// case. Mid-string matches (`"some text stream: true here"`) are NOT
// caught — same limitation as the hosted side, deliberately accepted
// for v1 since key strings rarely appear inside other content.
func TestUnboundedStreamSkipsCommentAndQuotedLiteral(t *testing.T) {
	src := `// stream: true without abort is a hang risk.
const tag = "stream: true";
const x = 1;`
	hits := scanUnboundedStream("doc.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits for comment + quote-leading literal, got %d", len(hits))
	}
}

// ── End-to-end walk ──────────────────────────────────────────────

func TestScanAiAppRegexWalksAndAggregates(t *testing.T) {
	tmp := t.TempDir()
	jsPath := filepath.Join(tmp, "src", "client.ts")
	if err := os.MkdirAll(filepath.Dir(jsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsPath, []byte(`const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;`), 0o644); err != nil {
		t.Fatal(err)
	}
	streamPath := filepath.Join(tmp, "src", "agent.ts")
	streamSrc := `const r = await openai.chat.completions.create({
  model: "gpt-4",
  stream: true,
});`
	if err := os.WriteFile(streamPath, []byte(streamSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	// node_modules must not be walked — a public-key reference inside
	// a vendored bundle would otherwise dominate the output.
	if err := os.MkdirAll(filepath.Join(tmp, "node_modules", "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(tmp, "node_modules", "vendor", "x.js"),
		[]byte(`const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	res, err := ScanAiAppRegex(tmp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Errorf("expected 2 findings (1 per source file), got %d: %+v", len(res.Findings), res.Findings)
	}
	cats := map[string]int{}
	for _, f := range res.Findings {
		cats[f.Category]++
	}
	if cats["client-side-llm-key"] != 1 || cats["unbounded-stream"] != 1 {
		t.Errorf("category mix off: %+v", cats)
	}
	if res.FilesScanned < 2 {
		t.Errorf("expected at least 2 files scanned, got %d", res.FilesScanned)
	}
}

// hashAiAppFinding stability — the dedup downstream relies on the
// hash being deterministic for the same (file, line, category, span).
func TestHashAiAppFindingDeterministic(t *testing.T) {
	a := hashAiAppFinding("src/x.ts", 3, "client-side-llm-key", "NEXT_PUBLIC_OPENAI_API_KEY")
	b := hashAiAppFinding("src/x.ts", 3, "client-side-llm-key", "NEXT_PUBLIC_OPENAI_API_KEY")
	if a != b {
		t.Errorf("hash drifted across calls: %q vs %q", a, b)
	}
	if a == "" {
		t.Error("hash should never be empty")
	}
	if !strings.HasPrefix(a, "") || len(a) == 0 {
		t.Errorf("hash looks malformed: %q", a)
	}
}
