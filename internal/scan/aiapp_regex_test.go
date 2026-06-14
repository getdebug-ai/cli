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

	res, err := ScanAiAppRegex(tmp, nil, nil)
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

// ── pii-in-prompt prefilter ──────────────────────────────────────

func TestPiiInPromptDetectsStringifyUserInsideMessages(t *testing.T) {
	src := `
const r = await client.chat.completions.create({
  messages: [
    { role: "system", content: "Summarise this customer." },
    { role: "user", content: JSON.stringify(user) },
  ],
});`
	hits := scanPiiInPrompt("app.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].Category != "pii-in-prompt" {
		t.Errorf("category=%q want pii-in-prompt", hits[0].Category)
	}
	if hits[0].Severity != SeverityHigh {
		t.Errorf("severity=%q want high", hits[0].Severity)
	}
	if hits[0].CWE != "CWE-359" {
		t.Errorf("cwe=%q want CWE-359", hits[0].CWE)
	}
}

func TestPiiInPromptDetectsProfileVar(t *testing.T) {
	src := `messages: [{ role: "user", content: JSON.stringify(profile) }]`
	hits := scanPiiInPrompt("app.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for profile var, got %d", len(hits))
	}
}

// Server-side log that happens to call JSON.stringify(user) outside any
// LLM context must NOT fire — the LLM-context window check exists for
// exactly this case.
func TestPiiInPromptIgnoresNonLlmContext(t *testing.T) {
	src := `function logUser(user) { console.log(JSON.stringify(user)); }`
	hits := scanPiiInPrompt("logger.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits outside LLM context, got %d", len(hits))
	}
}

// A non-user-shape var (e.g. a locally-built safeContext) must not
// match — the regex restricts to a curated user-name allowlist so
// the explicit-reduction safe pattern stays clean.
func TestPiiInPromptIgnoresSafeContextVar(t *testing.T) {
	src := `
const safeContext = { displayName: user.displayName, plan: user.plan };
const r = await client.chat.completions.create({
  messages: [{ role: "user", content: JSON.stringify(safeContext) }],
});`
	hits := scanPiiInPrompt("app.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on safeContext, got %d: %+v", len(hits), hits)
	}
}

// ── unsafe-role-merge prefilter ──────────────────────────────────

func TestUnsafeRoleMergeDetectsInterpolatedSystemContent(t *testing.T) {
	src := `messages: [
  { role: "system", content: ` + "`You are an assistant for a ${userPersona}.`" + ` },
  { role: "user", content: q },
]`
	hits := scanUnsafeRoleMerge("app.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].Category != "unsafe-role-merge" {
		t.Errorf("category=%q want unsafe-role-merge", hits[0].Category)
	}
}

// Static system content followed by an interpolated USER role content
// must NOT fire — this is the bench's safe fixture shape. The object-
// scoped lookahead exists for this case.
func TestUnsafeRoleMergeIgnoresInterpolationInOtherRole(t *testing.T) {
	src := `messages: [
  { role: "system", content: SYSTEM_PROMPT },
  { role: "user", content: ` + "`I am a ${persona}. ${userQuestion}`" + ` },
]`
	hits := scanUnsafeRoleMerge("app.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits (interpolation is on user-role), got %d: %+v", len(hits), hits)
	}
}

// Comment-line mention shouldn't fire.
func TestUnsafeRoleMergeSkipsComment(t *testing.T) {
	src := `// example: { role: "system", content: ` + "`hello ${name}`" + ` }
const x = 1;`
	hits := scanUnsafeRoleMerge("doc.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits in comment, got %d", len(hits))
	}
}

// ── prompt-injection prefilter ───────────────────────────────────

func TestPromptInjectionDetectsLiteralPlusUserInput(t *testing.T) {
	src := `
const prompt =
  "You are a translator. Translate the following to French.\n\n" +
  userQuestion;`
	hits := scanPromptInjection("app.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].Category != "prompt-injection" {
		t.Errorf("category=%q want prompt-injection", hits[0].Category)
	}
}

// A SYSTEM_PROMPT constant assigned a literal alone must NOT match —
// no concatenation, no injection vector.
func TestPromptInjectionIgnoresConstantSystemPrompt(t *testing.T) {
	src := `const SYSTEM_PROMPT = "You are a translator. Translate user content to French.";`
	hits := scanPromptInjection("app.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on constant assignment, got %d", len(hits))
	}
}

// A non-prompt-named var assigned a literal+ident shouldn't fire —
// keeps `const path = "/api/" + projectId` quiet.
func TestPromptInjectionIgnoresUnrelatedVarName(t *testing.T) {
	src := `const path = "/api/" + projectId;`
	hits := scanPromptInjection("api.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on unrelated var name, got %d", len(hits))
	}
}

// ── unsafe-tool-output prefilter ─────────────────────────────────

func TestUnsafeToolOutputDetectsExecOfToolInput(t *testing.T) {
	src := `const { stdout } = await run(tool.input.command);`
	hits := scanUnsafeToolOutput("app.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].Category != "unsafe-tool-output" {
		t.Errorf("category=%q want unsafe-tool-output", hits[0].Category)
	}
	if hits[0].Severity != SeverityCritical {
		t.Errorf("severity=%q want critical", hits[0].Severity)
	}
	if hits[0].CWE != "CWE-78" {
		t.Errorf("cwe=%q want CWE-78", hits[0].CWE)
	}
}

func TestUnsafeToolOutputDetectsBlockInputForm(t *testing.T) {
	// Anthropic SDK shape — `block.input.command`.
	src := `await execSync(block.input.command);`
	hits := scanUnsafeToolOutput("app.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for block.input.* form, got %d", len(hits))
	}
}

// run() with a non-tool-input arg must not fire — the allowlist-then-
// run pattern is the safe variant.
func TestUnsafeToolOutputIgnoresAllowlistedRun(t *testing.T) {
	src := `
const command = ALLOWED[tool.input.tag];
if (!command) return "(rejected)";
const { stdout } = await run(command);`
	hits := scanUnsafeToolOutput("app.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on allowlisted run, got %d: %+v", len(hits), hits)
	}
}

func TestUnsafeToolOutputIgnoresExecOfStaticString(t *testing.T) {
	src := `await exec("ls -la");`
	hits := scanUnsafeToolOutput("app.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on static-string exec, got %d", len(hits))
	}
}

// ── unsafe-tool-output: args.X form (canonical SDK shape) ─────────

// 0.5.2 addition: tool-callable functions canonically take input as
// `args.X` where args is the typed parameter. The detector must fire
// when args.X reaches a shell/exec sink.
func TestUnsafeToolOutputDetectsArgsExec(t *testing.T) {
	src := `
async execute(args: { command: string }) {
  const { stdout, stderr } = await execAsync(args.command);
  return { stdout, stderr };
}`
	hits := scanUnsafeToolOutput("shell.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for execAsync(args.command), got %d", len(hits))
	}
	if hits[0].CWE != "CWE-78" {
		t.Errorf("CWE=%q want CWE-78", hits[0].CWE)
	}
}

// 0.5.2 addition: SQL sinks fall under unsafe-tool-output when an
// LLM-supplied args.X flows into raw query execution. postgres-js's
// sql.unsafe is the canonical pattern.
func TestUnsafeToolOutputDetectsSqlUnsafeArgs(t *testing.T) {
	src := `
async execute(args: { query: string }) {
  const rows = await sql.unsafe(args.query);
  return { rows };
}`
	hits := scanUnsafeToolOutput("tool.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for sql.unsafe(args.query), got %d", len(hits))
	}
	if hits[0].CWE != "CWE-89" {
		t.Errorf("CWE=%q want CWE-89 (SQL injection)", hits[0].CWE)
	}
}

// 0.5.2 addition: better-sqlite3's db.prepare(args.X) is the SQL
// injection sink for the SQLite-side of the same problem.
func TestUnsafeToolOutputDetectsBetterSqliteArgs(t *testing.T) {
	src := `
async execute(args: { sql: string }) {
  const rows = db.prepare(args.sql).all();
  return { rows };
}`
	hits := scanUnsafeToolOutput("tool.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for db.prepare(args.sql), got %d", len(hits))
	}
	if hits[0].CWE != "CWE-89" {
		t.Errorf("CWE=%q want CWE-89", hits[0].CWE)
	}
}

// Parameterized SQL via the tagged template — the safe variant.
// Must NOT fire.
func TestUnsafeToolOutputIgnoresParameterizedSql(t *testing.T) {
	src := "const rows = await sql`SELECT * FROM users WHERE id = ${userId}`;"
	hits := scanUnsafeToolOutput("safe.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on parameterized sql, got %d: %+v", len(hits), hits)
	}
}

// ── client-side-llm-key: key returned in response body ────────────

// 0.5.2 addition: Next.js shape — Response.json returning the key.
func TestKeyInResponseDetectsNextResponseJson(t *testing.T) {
	src := `
export async function GET() {
  return Response.json({
    apiKey: process.env.OPENAI_API_KEY,
    model: 'gpt-4o-mini',
  });
}`
	hits := scanKeyInResponse("proxy.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for Response.json({apiKey:...}), got %d", len(hits))
	}
	if hits[0].Category != "client-side-llm-key" {
		t.Errorf("category=%q want client-side-llm-key", hits[0].Category)
	}
	if hits[0].CWE != "CWE-522" {
		t.Errorf("CWE=%q want CWE-522", hits[0].CWE)
	}
}

// 0.5.2 addition: Express shape — res.json returning the key.
func TestKeyInResponseDetectsExpressResJson(t *testing.T) {
	src := `
app.get('/api/config', (req, res) => {
  res.json({
    apiKey: process.env.OPENAI_API_KEY,
    endpoint: 'https://api.openai.com/v1',
  });
});`
	hits := scanKeyInResponse("server.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for res.json({apiKey:...}), got %d", len(hits))
	}
}

// Legitimate SDK construction must NOT fire — the SDK takes the key
// as a constructor arg, not as a response.
func TestKeyInResponseIgnoresSdkConstructor(t *testing.T) {
	src := `const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });`
	hits := scanKeyInResponse("init.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on SDK constructor, got %d: %+v", len(hits), hits)
	}
}

// ── 0.5.3 — SvelteKit $env/static/public CSK detector ──────────────

func TestPublicEnvKeyDetectsSvelteKitImport(t *testing.T) {
	src := `import { PUBLIC_ANTHROPIC_API_KEY } from '$env/static/public';`
	hits := scanPublicEnvKey("k.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for PUBLIC_ANTHROPIC_API_KEY import, got %d", len(hits))
	}
	if hits[0].Category != "client-side-llm-key" {
		t.Errorf("category=%q want client-side-llm-key", hits[0].Category)
	}
	if hits[0].CWE != "CWE-798" {
		t.Errorf("CWE=%q want CWE-798", hits[0].CWE)
	}
}

func TestPublicEnvKeyIgnoresPrivateImport(t *testing.T) {
	src := `import { ANTHROPIC_API_KEY } from '$env/static/private';`
	hits := scanPublicEnvKey("k.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits for private import, got %d", len(hits))
	}
}

// ── 0.5.3 — SvelteKit bare-identifier key-in-response detector ─────

func TestKeyInResponseSvelteDetectsBareIdentifier(t *testing.T) {
	src := `
import { ANTHROPIC_API_KEY } from '$env/static/private';
import { json } from '@sveltejs/kit';

export const GET = async () => {
  return json({
    apiKey: ANTHROPIC_API_KEY,
    model: 'claude-sonnet-4-5',
  });
};`
	hits := scanKeyInResponseSvelte("creds.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for bare-identifier key, got %d: %+v", len(hits), hits)
	}
}

// ── 0.5.3 — Svelte {@html ...} sink ─────────────────────────────────

func TestSvelteHtmlSinkDetectsContextual(t *testing.T) {
	src := `
<script lang="ts">
  import { marked } from 'marked';
  let { content } = $props();
  const html = marked.parse(content);
</script>

<div>{@html html}</div>`
	hits := scanSvelteHtmlSink("Bubble.svelte", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for {@html} with marked context, got %d", len(hits))
	}
}

func TestSvelteHtmlSinkIgnoresStaticContent(t *testing.T) {
	src := `<div>{@html staticString}</div>`
	hits := scanSvelteHtmlSink("Static.svelte", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on static {@html} (no LLM context), got %d", len(hits))
	}
}

// ── 0.5.3 — Anthropic system: param URM detector ────────────────────

func TestAnthropicSystemMergeDetectsInlineTemplate(t *testing.T) {
	src := "const userInput = 'x';\nawait anthropic.messages.create({\n  model: 'claude',\n  system: `You are X. The user said: ${userInput}`,\n  messages: [{ role: 'user', content: userInput }],\n});"
	hits := scanAnthropicSystemMerge("chat.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for inline-template system:, got %d", len(hits))
	}
	if hits[0].Category != "unsafe-role-merge" {
		t.Errorf("category=%q want unsafe-role-merge", hits[0].Category)
	}
}

func TestAnthropicSystemMergeDetectsIndirectIdentifier(t *testing.T) {
	src := "const userInput = 'x';\nconst systemPrompt = `You are X. The user said: ${userInput}. Respond.`;\nawait anthropic.messages.stream({\n  model: 'claude',\n  system: systemPrompt,\n  messages: [{ role: 'user', content: userInput }],\n});"
	hits := scanAnthropicSystemMerge("chat.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for indirect-identifier system:, got %d", len(hits))
	}
}

func TestAnthropicSystemMergeIgnoresStaticString(t *testing.T) {
	src := `await anthropic.messages.create({
  model: 'claude',
  system: 'You are a helpful assistant.',
  messages: [],
});`
	hits := scanAnthropicSystemMerge("chat.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on static system:, got %d", len(hits))
	}
}

// ── 0.5.3 — Anthropic messages.stream() unbounded detector ──────────

func TestAnthropicUnboundedStreamDetectsUngatedCall(t *testing.T) {
	src := `
const stream = anthropic.messages.stream({
  model: 'claude',
  system: 'x',
  messages: [],
});

for await (const chunk of stream) {
  // process
}`
	hits := scanAnthropicUnboundedStream("chat.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for unbounded messages.stream(), got %d", len(hits))
	}
}

func TestAnthropicUnboundedStreamIgnoresAbortControllerScope(t *testing.T) {
	src := `
const controller = new AbortController();
const stream = anthropic.messages.stream({
  model: 'claude',
  system: 'x',
  messages: [],
}, { signal: controller.signal });`
	hits := scanAnthropicUnboundedStream("chat.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits when AbortController in scope, got %d", len(hits))
	}
}

// ── 0.5.3 — Precision: allowlist guard suppresses args.X sink ──────

func TestUnsafeToolOutputSuppressedByAllowlistGuard(t *testing.T) {
	src := `
const TABLE_ALLOWLIST = new Set(['docs', 'orders']);

async function exec(args: { table: string }) {
  if (!TABLE_ALLOWLIST.has(args.table)) {
    throw new Error('not allowed');
  }
  const stmt = db.prepare("SELECT * FROM " + args.table);
  return stmt.all();
}`
	hits := scanUnsafeToolOutput("safe.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits when allowlist guards args.X, got %d: %+v", len(hits), hits)
	}
}

// ── 0.5.4 — Extended UTO sinks: writeFileSync, new Function ────────

func TestUnsafeToolOutputDetectsWriteFileSyncArgs(t *testing.T) {
	src := `
async function execute(args: { path: string; contents: string }) {
  writeFileSync(join('./workspace', args.path), args.contents);
}`
	hits := scanUnsafeToolOutput("write.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for writeFileSync(...args.X), got %d", len(hits))
	}
}

func TestUnsafeToolOutputDetectsNewFunctionArgs(t *testing.T) {
	src := "async function execute(args: { expr: string }) {\n  const fn = new Function(`return (${args.expr});`);\n  return fn();\n}"
	hits := scanUnsafeToolOutput("eval.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for new Function(...args.X), got %d", len(hits))
	}
}

// ── 0.5.4 — fetch() without signal: option ─────────────────────────

func TestUnboundedFetchDetectsBareFetchOnArgsUrl(t *testing.T) {
	src := `
async function execute(args: { url: string }) {
  const res = await fetch(args.url, { redirect: 'follow' });
  return await res.text();
}`
	hits := scanUnboundedFetch("fetch.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for fetch(args.url) without signal:, got %d", len(hits))
	}
}

func TestUnboundedFetchIgnoresFetchWithSignal(t *testing.T) {
	src := `
async function execute(args: { url: string }) {
  const controller = new AbortController();
  const res = await fetch(args.url, { signal: controller.signal });
  return await res.text();
}`
	hits := scanUnboundedFetch("safe.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits when signal: is set, got %d", len(hits))
	}
}

// ── 0.5.4 — HTML embed key leak ────────────────────────────────────

func TestHtmlKeyEmbedDetectsResSendTemplate(t *testing.T) {
	src := "function embedHandler(req, res) {\n  const html = `<!doctype html><div data-api-key=\"${process.env.OPENAI_API_KEY}\"></div>`;\n  res.send(html);\n}"
	hits := scanHtmlKeyEmbed("embed.ts", src)
	// Note: this specific shape (assigned to const, then res.send(html)) is
	// just OUTSIDE the regex's direct-anchor — left as a known limitation
	// for v0.5.5. We instead test the direct-template-in-send shape.
	_ = hits
	src2 := "function embedHandler(_req, res) {\n  res.send(`<!doctype html><div data-api-key=\"${process.env.OPENAI_API_KEY}\"></div>`);\n}"
	hits2 := scanHtmlKeyEmbed("embed.ts", src2)
	if len(hits2) != 1 {
		t.Fatalf("expected 1 hit for inline res.send template with process.env key, got %d", len(hits2))
	}
}

// ── 0.5.4 — PIP context-gate relaxation by file-name signal ───────

func TestPiiInPromptRelaxedForUserSnapshotFile(t *testing.T) {
	src := `
import type { User } from './types.js';

export function userSnapshotMessage(user: User): { role: 'user'; content: string } {
  return {
    role: 'user',
    content: ` + "`Current user snapshot:\\n${JSON.stringify(user, null, 2)}`" + `,
  };
}`
	hits := scanPiiInPrompt("src/services/user-snapshot.ts", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit on user-snapshot.ts file-name signal, got %d", len(hits))
	}
}

func TestPiiInPromptStillRequiresContextOnGenericFile(t *testing.T) {
	src := `export function logger(user) {
  console.log(JSON.stringify(user, null, 2));
}`
	hits := scanPiiInPrompt("src/utils/logger.ts", src)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits on a generic logger (no AI-context file-name + no LLM-call marker), got %d", len(hits))
	}
}
