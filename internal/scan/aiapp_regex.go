// AI-app regex prefilters — Phase 1.7 Item 1b.
//
// Port of the regex-only patterns from workers/src/security/llm-app.ts
// (CLIENT_SIDE_LLM_KEY and UNBOUNDED_STREAM). Deterministic, no LLM call,
// no network — runs alongside the secrets pass on every analyze.
//
// Why this exists: the local LLM SAST shipped in Phase 1.7 Item 1 covers
// these categories via the model, but a small local model misses
// well-defined regex shapes that the hosted side already catches with
// these prefilters. Adding them locally closes the precision/recall gap
// without requiring Ollama at all — every getdebug analyze gets
// AI-free coverage for two more categories.
//
// Categories:
//   - client-side-llm-key (CWE-798, severity critical) — an LLM
//     provider key referenced via NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_/etc.
//     env vars that frameworks inline into the client bundle. If the
//     pattern matches, this IS a key leak.
//   - unbounded-stream (CWE-770, severity medium) — `stream: true` on
//     an LLM call with no AbortController in the surrounding ±40-line
//     scope. The TextDecoder.decode({ stream: true }) Web-Streams shape
//     is filtered out explicitly (most common false positive).
//
// Both prefilters use the same comment/string-literal skip the hosted
// helpers apply, so doc examples and changelogs don't fire.

package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Severity floors for the six categories. Mirror the hosted defaults
// from workers/src/security/llm-app.ts. The CLI's sastlocal pass has
// its own floor enforcement; this surface keeps the same contract.
const (
	clientLlmKeySeverity    = SeverityCritical
	unboundedStreamSeverity = SeverityMedium
	piiInPromptSeverity     = SeverityHigh
	unsafeRoleMergeSeverity = SeverityHigh
	promptInjectionSeverity = SeverityHigh
	unsafeToolOutputSeverity = SeverityCritical
)

// Same provider-name list the hosted side uses — narrow + capitalised
// so loose word matches like "AI" don't over-fire. Drift between
// hosted + local hurts precision symmetry.
var clientLlmKeyRe = regexp.MustCompile(
	`(?:process\.env|import\.meta\.env|Bun\.env)\.((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|PUBLIC|REACT_APP)_[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|XAI|GROK|COHERE|MISTRAL|PERPLEXITY|DEEPSEEK|GROQ|REPLICATE|HUGGINGFACE|TOGETHER|FIREWORKS|OLLAMA)[A-Z0-9_]*(?:KEY|API_KEY|SECRET|TOKEN))\b`,
)

var streamTrueDetectorRe = regexp.MustCompile(`\bstream\s*:\s*true\b`)

// decoder.decode(...{stream:true...}) — the false positive the hosted
// side specifically filters. Look back ≤80 chars from the match for an
// unclosed `.decode(`.
var decoderDecodeLookbackRe = regexp.MustCompile(`\.decode\s*\([^)]*$`)

// AbortController / signal: / .abort( in the surrounding window means
// the stream is bounded already. Skip.
var abortInScopeRe = regexp.MustCompile(`\b(?:AbortController|signal\s*:|\.abort\s*\()`)

// ── pii-in-prompt prefilter ──────────────────────────────────────
//
// Detects a high-signal anti-pattern: an entire user-shape object is
// JSON.stringify'd into an LLM message. The bench's vulnerable fixture
// uses `JSON.stringify(user)`; the safe variant builds a small
// `safeContext` first. We fire only on the curated user-shape names
// to keep precision high. A JSON.stringify(arbitraryVar) doesn't
// match — there are too many legitimate callers.
var piiInPromptRe = regexp.MustCompile(
	`\bJSON\.stringify\s*\(\s*(user|profile|account|customer|member|currentUser|loggedInUser|userInfo|userData|userProfile|userRecord|userObject|personalInfo|personalDetails)\b`,
)

// LLM-call markers within the ±20-line context window. The same
// JSON.stringify shape outside an LLM call is e.g. a server log or a
// REST response — not in scope.
var llmCallContextRe = regexp.MustCompile(
	`(?:messages\s*:|chat\.completions\.create|messages\.create|generateContent|complete\s*\(|\.invoke\s*\(|prompt\s*:)`,
)

// ── unsafe-role-merge prefilter ──────────────────────────────────
//
// A `role: "system"` message whose `content` is a template literal
// containing `${...}` interpolation. The safe pattern uses static
// strings or constants for system content; user-controlled text rides
// the user-role channel.
//
// We match a `role: "system"` marker, then look ahead up to 240 chars
// in the same message-object for a content field that's a template
// literal carrying a `${}` interpolation.
var systemRoleMarkerRe = regexp.MustCompile(`\brole\s*:\s*["']system["']`)
var contentInterpolatedRe = regexp.MustCompile("content\\s*:\\s*`[^`]*\\$\\{[^}]+\\}[^`]*`")

// ── prompt-injection prefilter ───────────────────────────────────
//
// Detects the assignment form: a `prompt`-shaped variable assigned a
// string literal concatenated with an identifier (likely user input).
// The safe pattern keeps system instructions in a const and routes
// user input through the user-role channel.
//
// Multi-line concat needs (?s) so `.` spans newlines. The fixture
// concatenates across three lines:
//   const prompt =
//     "You are a translator. ..." +
//     userQuestion;
var promptConcatRe = regexp.MustCompile(
	`(?s)(?:const|let|var)\s+(?:prompt|fullPrompt|systemPrompt|userPrompt|finalPrompt|completePrompt|combinedPrompt|message|query)\b\s*=\s*"[^"]*"\s*\+\s*[a-zA-Z_$]`,
)

// ── unsafe-tool-output prefilter ─────────────────────────────────
//
// A shell/exec sink called with a tool-output reference as its first
// argument. The Anthropic + OpenAI SDKs surface tool output as
// `block.input.<field>`, `tool.input.<field>`, `toolUse.input.<field>`,
// `toolCall.arguments.<field>`. The safe pattern routes that field
// through an allowlist before calling the shell.
//
// Sinks: exec / execSync / spawn / spawnSync / eval / Function() +
// promisified-exec wrappers commonly named `run`. We deliberately
// include `run` because the bench fixture uses
// `run = promisify(exec)` — the same name a hand-rolled wrapper would
// take. Tightened by the must-reference-tool-input requirement so
// `run("ls")` doesn't fire.
var unsafeToolOutputRe = regexp.MustCompile(
	`\b(?:exec|execSync|spawn|spawnSync|eval|run|runCommand|runSync)\s*\(\s*[^)]*?\b(?:tool|toolUse|toolCall|block|toolResult|toolOutput|message|response)\.(?:input|arguments|args|parameters|result|content)\.`,
)

// unsafeToolOutputArgsRe catches the canonical SDK tool-function shape
// where args.X (the typed function parameter) flows into a dangerous
// sink. Anthropic + OpenAI tool-callable functions take the SDK's
// validated input as `args` by convention:
//
//   async execute(args: { command: string }) {
//     await execAsync(args.command);   // ← canonical sink
//   }
//
// SQL sinks are included alongside shell sinks: postgres-js's
// `sql.unsafe(args.X)` bypasses parameterization the same way `exec`
// bypasses the shell. better-sqlite3's `db.prepare(args.X).all()` is
// the same shape under a different name.
// 0.5.4 — added file-write sinks (writeFileSync, writeFile,
// appendFileSync, appendFile, createWriteStream) and Function-form
// code-injection sinks. writeFileSync(args.path, ...) is the canonical
// path-traversal sink in the agent-framework idiom; `new Function(...)`
// (the Function constructor) is eval's less-obvious sibling.
var unsafeToolOutputArgsRe = regexp.MustCompile(
	`\b(?:exec|execSync|execAsync|spawn|spawnSync|eval|run|runCommand|runSync|sql\.unsafe|db\.unsafe|db\.query|pool\.unsafe|pool\.query|client\.unsafe|client\.query|db\.prepare|writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|Function)\s*\(\s*[^)]{0,200}?\bargs\.\w+`,
)

// unboundedFetchRe — 0.5.4 addition.
// `fetch(<arg containing args.X>, ...)` without a `signal:` option in
// the opts object. Catches the tool-side streaming-fetch pattern the
// stream:true and messages.stream detectors miss.
var unboundedFetchRe = regexp.MustCompile(
	`\bfetch\s*\(\s*[^,)]{0,160}?\bargs\.\w+`,
)

// signalInFetchOptsRe — used to gate unboundedFetchRe hits. If the
// surrounding call has a `signal:` key in the opts object, suppress.
var signalInFetchOptsRe = regexp.MustCompile(
	`\bsignal\s*:`,
)

// htmlKeyEmbedRe — 0.5.4 addition.
// `res.send` / `response.send` / `reply.send` of a backtick-quoted
// template literal that contains `process.env.X_API_KEY` (or similar)
// embedded as an HTML attribute or text node. Semantically equivalent
// to NEXT_PUBLIC_ exposure but via server-rendered HTML.
var htmlKeyEmbedRe = regexp.MustCompile(
	"(?s)\\b(?:res\\.send|response\\.send|reply\\.send)\\s*\\(\\s*`[^`]{0,800}?\\$\\{\\s*process\\.env\\.[A-Z][A-Z0-9_]*(?:_API_KEY|_KEY|_TOKEN|_SECRET)\\s*\\}",
)

// aiAppFileNameSignalRe — 0.5.4 addition.
// When the FILE name signals AI-app context (user-snapshot.ts,
// profile-context.ts, prompt-builder.ts, etc.) the piiInPromptRe
// finding fires without requiring an LLM-call marker in the same
// file's ±20-line window. Catches the cross-file case where the
// helper that JSON.stringify's the user is imported by the LLM-
// calling route.
var aiAppFileNameSignalRe = regexp.MustCompile(
	`(?i)(?:[/-]|^)(?:user-snapshot|profile-context|prompt-builder|prompt-context|message-builder|conversation-context|chat-context|system-prompt|user-context|llm-context)\.(?:ts|tsx|js|jsx|mjs|cjs|py|svelte\.ts|svelte\.js)$`,
)

// keyInResponseRe catches a server route returning an LLM provider API
// key in the JSON response body. Pattern: a Response.json / res.json /
// `return json` call whose body has an apiKey/secret/token property
// whose value is `process.env.X_API_KEY` (or similar). The (?s) flag
// allows the body to span lines.
//
// Semantically equivalent to shipping the key in the client bundle —
// hidden behind an unauthed GET instead of inlined into the bundle.
// Categorised as client-side-llm-key because the effect is identical
// (key reaches the browser).
var keyInResponseRe = regexp.MustCompile(
	`(?s)(?:Response\.json|res\.json|res\.send|return\s+json|return\s+Response\.json)\s*\(\s*\{[^}]{0,400}?(?:apiKey|api_key|secret|token|key)\s*:\s*process\.env\.[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET)`,
)

// keyInResponseSvelteRe — 0.5.3 addition.
// SvelteKit's `$env/static/private` injects env vars as bare imported
// identifiers (not via process.env). The leak shape is:
//
//   import { ANTHROPIC_API_KEY } from '$env/static/private';
//   return json({ apiKey: ANTHROPIC_API_KEY, ... });
//
// We detect the response side (json(...) call with an apiKey/secret/
// token property whose value is a bare UPPERCASE_*_KEY identifier).
// The same shape works for any framework that lets the user destructure
// env vars from a module — SvelteKit is the canonical case but Next.js
// also supports it via `@/lib/env`-style indirection.
var keyInResponseSvelteRe = regexp.MustCompile(
	`(?s)(?:Response\.json|return\s+json|return\s+Response\.json|res\.json)\s*\(\s*\{[^}]{0,400}?(?:apiKey|api_key|secret|token|key)\s*:\s*[A-Z][A-Z0-9_]*(?:_API_KEY|_KEY|_TOKEN|_SECRET)\b`,
)

// publicEnvKeyRe — 0.5.3 addition.
// Catches the SvelteKit / Astro / Nuxt shape of the same NEXT_PUBLIC_
// mistake: `import { PUBLIC_FOO_API_KEY } from '$env/static/public'`.
// SvelteKit physically inlines anything from $env/static/public into
// the client bundle (same contract as NEXT_PUBLIC_); the existing
// clientLlmKeyRe only matches process.env / import.meta.env / Bun.env
// access patterns, not the destructured import shape.
var publicEnvKeyRe = regexp.MustCompile(
	`import\s*\{[^}]*\b(PUBLIC_[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|XAI|GROK|COHERE|MISTRAL|PERPLEXITY|DEEPSEEK|GROQ|REPLICATE|HUGGINGFACE|TOGETHER|FIREWORKS|OLLAMA)[A-Z0-9_]*(?:KEY|API_KEY|SECRET|TOKEN))\b[^}]*\}\s*from\s*['"]\$env/static/public['"]`,
)

// svelteHtmlSinkRe — 0.5.3 addition.
// Svelte's `{@html X}` directive is the equivalent of React's
// `dangerouslySetInnerHTML` — it renders untrusted HTML into the DOM
// with no sanitization. When X comes from tool/assistant content
// (anywhere in the same file), it's an XSS sink for attacker-
// controllable LLM output. We require a marked.parse / tool / assistant
// reference within ±40 lines so plain `{@html staticString}` doesn't
// over-fire.
var svelteHtmlSinkRe = regexp.MustCompile(`\{\s*@html\s+\w+`)
var svelteHtmlContextRe = regexp.MustCompile(
	`(?:marked\.parse|role\s*===?\s*['"](?:assistant|tool)['"]|toolUse|tool_use|messages\b|content\s*:)`,
)

// anthropicSystemParamRe — 0.5.3 addition.
// Anthropic's SDK takes the system prompt as a top-level `system:`
// parameter, NOT as a `role: 'system'` message inside `messages[]`.
// The existing scanUnsafeRoleMerge detector matches the messages-array
// shape and structurally cannot see Anthropic's separate `system:`
// parameter. This detector mirrors it: `system: <template literal with
// interpolation>` inside an .messages.create / .messages.stream call.
var anthropicSystemParamRe = regexp.MustCompile(
	"(?s)\\.messages\\.(?:create|stream)\\s*\\([^)]{0,400}?system\\s*:\\s*`[^`]*\\$\\{[^}]+\\}",
)
var anthropicSystemParamIdentRe = regexp.MustCompile(
	`(?s)\.messages\.(?:create|stream)\s*\([^)]{0,400}?system\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[,)]`,
)
// templateConcatAssignedRe matches `const NAME = \`...${X}...\`` for the
// purpose of confirming an identifier referenced by anthropicSystemParamIdentRe
// was built from a template-literal concat. (?s) so backticks can span lines.
var templateConcatAssignedRe = regexp.MustCompile(
	"(?s)(?:const|let|var)\\s+(\\w+)\\s*=\\s*`[^`]*\\$\\{[^}]+\\}[^`]*`",
)
// systemTernaryAssignedRe matches `const NAME = cond ? \`...${X}...\` : ...`
// for the ternary-with-template-literal shape (used in cst-sveltekit-stream's
// chat/+server.ts). (?s) so the ternary body can span lines.
var systemTernaryAssignedRe = regexp.MustCompile(
	"(?s)(?:const|let|var)\\s+(\\w+)\\s*=\\s*[^;]+\\?\\s*`[^`]*\\$\\{[^}]+\\}",
)

// anthropicStreamCallRe — 0.5.3 addition.
// Anthropic's streaming form is a method call (`anthropic.messages.stream(`)
// rather than OpenAI's `stream: true` property. The existing
// streamTrueDetectorRe only matches the property form. This regex
// catches the Anthropic shape; abort-in-scope check still gates whether
// it counts as unbounded.
var anthropicStreamCallRe = regexp.MustCompile(
	`\.messages\.stream\s*\(`,
)

// allowlistGuardRe — 0.5.3 addition.
// Precision improvement: when a `db.prepare(args.X)` (or sql.unsafe etc.)
// is preceded within ~10 lines by an allowlist check on the SAME args
// field (`if (!ALLOWLIST.has(args.X))` or `if (!ALLOWED.has(args.X))`),
// suppress the unsafeToolOutputArgs hit. Reduces FP on table-allowlist
// guarded query patterns.
var allowlistGuardRe = regexp.MustCompile(
	`(?:if\s*\(\s*!?\s*[A-Z_][A-Z0-9_]*(?:_ALLOWLIST|_ALLOWED|_ALLOW|ALLOWLIST|ALLOWED|ALLOW)\.has\s*\(\s*args\.(\w+)\s*\))`,
)

// AiAppRegexResult mirrors the existing scan-pass return shapes so the
// CLI's analyze command can emit honest coverage numbers (files
// considered, scanned, errors, etc.) the same way as secrets +
// sastlocal.
type AiAppRegexResult struct {
	Findings        []Finding
	FilesConsidered int
	FilesScanned    int
	FilesSkipped    int
	Errors          int
}

// ScanAiAppRegex walks workdir for JS/TS/JSX/TSX files and applies both
// regex prefilters. Mirrors the file-walk shape secrets.go uses, with
// the same vendor + lockfile skips, so a clean analyze run never
// double-walks. Best-effort: read errors are logged via logf and the
// walk continues.
func ScanAiAppRegex(workdir string, rules *IgnoreRuleset, logf func(format string, args ...any)) (*AiAppRegexResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	res := &AiAppRegexResult{Findings: []Finding{}}
	err := filepath.WalkDir(workdir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logf("ai-app regex: walk error at %s: %v — continuing", path, err)
			return nil
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			if strings.HasPrefix(d.Name(), ".getdebug-backup-") {
				return filepath.SkipDir
			}
			if rules != nil {
				relDir, relErr := filepath.Rel(workdir, path)
				if relErr == nil && rules.IsDirIgnored(filepath.ToSlash(relDir)) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))
		// `.svelte` and `.svelte.ts` / `.svelte.js` files contain JS/TS
		// that should be scanned alongside the regular JS/TS extensions.
		// 0.5.3 — added .svelte support to catch Svelte-specific
		// patterns (`{@html ...}`, `$env/static/public` imports) plus
		// the existing JS regexes that work inside `<script lang="ts">`
		// blocks.
		isSvelte := strings.HasSuffix(name, ".svelte") || strings.HasSuffix(name, ".svelte.ts") || strings.HasSuffix(name, ".svelte.js")
		switch {
		case ext == ".ts", ext == ".tsx", ext == ".js", ext == ".jsx", ext == ".mjs", ext == ".cjs", ext == ".py", ext == ".go", ext == ".rb":
			// supported. .go (0.5.7) and .rb (0.5.8) added — both gated to
			// LLM-SDK files inside their scanners so non-AI code stays silent.
		case isSvelte:
			// supported via the JS dispatcher.
		default:
			return nil
		}
		rel, err := filepath.Rel(workdir, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		if rules != nil && rules.IsIgnored(rel) {
			return nil
		}
		res.FilesConsidered++
		info, err := d.Info()
		if err != nil {
			res.FilesSkipped++
			return nil
		}
		// Same per-file size cap as the local SAST pass. A megabyte of
		// generated JS bundle has no source-of-truth value here.
		if info.Size() > 256*1024 {
			res.FilesSkipped++
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			res.Errors++
			logf("ai-app regex: read %s: %v — skipping", path, err)
			return nil
		}
		res.FilesScanned++
		res.Findings = append(res.Findings, scanAiAppRegex(rel, string(raw))...)
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// scanAiAppRegex applies every prefilter to one file's source.
// Dispatch by file extension: JS/TS files go through the original
// scanners (which fire on `process.env.NEXT_PUBLIC_*` etc.), Python
// files go through the Python-idiom scanners.
func scanAiAppRegex(relPath, source string) []Finding {
	switch ext := lowerExt(relPath); ext {
	case ".py":
		return scanAiAppRegexPython(relPath, source)
	case ".go":
		return scanAiAppRegexGo(relPath, source)
	case ".rb":
		return scanAiAppRegexRuby(relPath, source)
	default:
		return scanAiAppRegexJS(relPath, source)
	}
}

// scanAiAppRegexJS runs the JS/TS prefilter set. Same as the
// original combined scanner; extracted so the dispatcher above can
// route Python to its own scanner without dead-firing JS-only
// patterns (NEXT_PUBLIC_ etc.) on .py files.
func scanAiAppRegexJS(relPath, source string) []Finding {
	var out []Finding
	out = append(out, scanClientSideLlmKey(relPath, source)...)
	out = append(out, scanPublicEnvKey(relPath, source)...)
	out = append(out, scanKeyInResponse(relPath, source)...)
	out = append(out, scanKeyInResponseSvelte(relPath, source)...)
	out = append(out, scanHtmlKeyEmbed(relPath, source)...)
	out = append(out, scanUnboundedStream(relPath, source)...)
	out = append(out, scanAnthropicUnboundedStream(relPath, source)...)
	out = append(out, scanUnboundedFetch(relPath, source)...)
	out = append(out, scanAnthropicSystemMerge(relPath, source)...)
	out = append(out, scanSvelteHtmlSink(relPath, source)...)
	out = append(out, scanPiiInPrompt(relPath, source)...)
	out = append(out, scanUnsafeRoleMerge(relPath, source)...)
	out = append(out, scanPromptInjection(relPath, source)...)
	out = append(out, scanUnsafeToolOutput(relPath, source)...)
	return out
}

// lowerExt returns the lowercase file extension including the dot.
// Inline because filepath.Ext + strings.ToLower at every walk step
// shows up in profiles on large repos.
func lowerExt(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return ""
		}
		if p[i] == '.' {
			ext := p[i:]
			// Manual ASCII-lower — alloc-free for common cases.
			b := make([]byte, len(ext))
			for j := 0; j < len(ext); j++ {
				c := ext[j]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				b[j] = c
			}
			return string(b)
		}
	}
	return ""
}

// scanClientSideLlmKey applies the CLIENT_SIDE_LLM_KEY prefilter from
// workers/src/security/llm-app.ts. Deterministic — every match is a
// real key leak (severity critical).
func scanClientSideLlmKey(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range clientLlmKeyRe.FindAllStringSubmatchIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		matchedSpan := source[loc[2]:loc[3]] // capture group 1: the env var name
		line := lineNumberAt(source, matchStart)
		title := "LLM provider key exposed to client bundle"
		explanation := "An LLM provider API key is being referenced through a build-time public env var. Frameworks like Next.js (NEXT_PUBLIC_*), Vite (VITE_*), and Expo (EXPO_PUBLIC_*) inline these values into the client bundle — once shipped, the key is published. Move the call to a server route or API handler and read the key from a non-public env var."
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "client-side-llm-key",
			Severity:    clientLlmKeySeverity,
			Title:       title,
			Explanation: explanation,
			ContentHash: hashAiAppFinding(relPath, line, "client-side-llm-key", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-798",
			OWASP:       "A02",
			Detection:   "regex",
		})
	}
	return out
}

// scanUnboundedStream applies the UNBOUNDED_STREAM prefilter from
// workers/src/security/llm-app.ts. Heuristic — skips TextDecoder
// false-positives explicitly and clears any stream:true that has an
// AbortController shape within ±40 lines.
func scanUnboundedStream(relPath, source string) []Finding {
	var out []Finding
	lines := strings.Split(source, "\n")
	for _, loc := range streamTrueDetectorRe.FindAllStringIndex(source, -1) {
		pos := loc[0]
		if inNonCodeContext(source, pos) {
			continue
		}
		// TextDecoder.decode({stream: true}) — Web Streams API, not LLM.
		lookbackStart := pos - 80
		if lookbackStart < 0 {
			lookbackStart = 0
		}
		if decoderDecodeLookbackRe.MatchString(source[lookbackStart:pos]) {
			continue
		}
		line := lineNumberAt(source, pos)
		// ±40 line window for AbortController scope check.
		from := line - 1 - 40
		if from < 0 {
			from = 0
		}
		to := line + 40
		if to > len(lines) {
			to = len(lines)
		}
		window := strings.Join(lines[from:to], "\n")
		if abortInScopeRe.MatchString(window) {
			continue
		}
		matchedSpan := source[loc[0]:loc[1]]
		title := "Streaming LLM call without abort handling"
		explanation := "A streaming LLM call (stream: true) has no AbortController / signal in its surrounding scope. If the client disconnects or the model hangs, the request keeps a worker slot occupied and continues billing tokens. Pass `signal: controller.signal` and abort the controller when the caller leaves."
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unbounded-stream",
			Severity:    unboundedStreamSeverity,
			Title:       title,
			Explanation: explanation,
			ContentHash: hashAiAppFinding(relPath, line, "unbounded-stream", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-770",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanPiiInPrompt fires when an entire user-shape object is
// JSON.stringify'd into an LLM message. Requires both the curated
// user-name match AND an LLM-call marker within ±20 lines to keep
// FPs out of server-log call sites.
func scanPiiInPrompt(relPath, source string) []Finding {
	var out []Finding
	lines := strings.Split(source, "\n")
	for _, loc := range piiInPromptRe.FindAllStringSubmatchIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		line := lineNumberAt(source, matchStart)
		// ±20 line window for LLM-call context.
		from := line - 1 - 20
		if from < 0 {
			from = 0
		}
		to := line + 20
		if to > len(lines) {
			to = len(lines)
		}
		window := strings.Join(lines[from:to], "\n")
		// 0.5.4 — if the file name signals AI-app context
		// (user-snapshot.ts, profile-context.ts, prompt-builder.ts, etc.)
		// the LLM-call-marker gate is relaxed. The helper that
		// JSON.stringify's the user is imported by the LLM-calling
		// route; the LLM call lives in a different file by design.
		fileNameSignals := aiAppFileNameSignalRe.MatchString(relPath)
		if !fileNameSignals && !llmCallContextRe.MatchString(window) {
			continue
		}
		matchedSpan := source[loc[2]:loc[3]] // capture group 1: the var name
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "pii-in-prompt",
			Severity:    piiInPromptSeverity,
			Title:       "User PII serialised into LLM prompt",
			Explanation: "JSON.stringify on a user-shape variable inside an LLM call sends every field — email, phone, address, DOB — to the provider's logs and may end up in their retention/training pipeline. Reduce the payload to the fields the task actually needs before serialising, or pull out just the display fields at the call site.",
			ContentHash: hashAiAppFinding(relPath, line, "pii-in-prompt", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-359",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanUnsafeRoleMerge fires when a `role: "system"` message has a
// template-literal `content` that interpolates a `${...}` value.
// Catches the common AI-app smell of building system instructions
// out of user-controlled strings.
//
// The lookahead is bounded by the message-object's closing `}` so a
// system-role message with a STATIC content followed by a user-role
// message with an interpolated content doesn't falsely fire — the
// scan stops before reaching the next message in the array.
func scanUnsafeRoleMerge(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range systemRoleMarkerRe.FindAllStringIndex(source, -1) {
		pos := loc[0]
		if inNonCodeContext(source, pos) {
			continue
		}
		// Walk forward from end-of-`role:"system"` to the matching `}`
		// that closes the surrounding message object, tracking brace
		// depth so nested object/template-literal braces don't trick
		// the boundary. Cap at 600 chars — well past any reasonable
		// single message but short enough to bail on malformed source.
		objectEnd := findObjectEnd(source, loc[1], 600)
		if objectEnd <= loc[1] {
			continue
		}
		window := source[loc[1]:objectEnd]
		ileft := contentInterpolatedRe.FindStringIndex(window)
		if ileft == nil {
			continue
		}
		matchAbs := loc[1] + ileft[0]
		line := lineNumberAt(source, matchAbs)
		matchedSpan := window[ileft[0]:ileft[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "User-controlled string interpolated into system role",
			Explanation: "A `role: \"system\"` message contains template-literal interpolation, suggesting user-controlled values are reaching the system channel. Models treat the system role with operator-level authority — letting untrusted text in there bypasses much of the safety training and prompt-injection mitigations. Keep system content static; route variable inputs through the user role.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-1039",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// findObjectEnd returns the index of the `}` that closes the object
// containing position `start`. We assume `start` is inside an object
// literal (after `role: "system"` which is necessarily inside one).
// Tracks brace depth, ignoring braces that appear inside string or
// template-literal tokens. Returns `start` (caller bails) when no
// matching close is found within `maxScan` chars.
func findObjectEnd(source string, start, maxScan int) int {
	end := start + maxScan
	if end > len(source) {
		end = len(source)
	}
	depth := 1 // we're already inside the object containing `role: "system"`
	i := start
	for i < end {
		c := source[i]
		switch c {
		case '"', '\'':
			i = skipString(source, i, c, end)
			continue
		case '`':
			i = skipTemplate(source, i, end)
			continue
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return start
}

// skipString moves past a single- or double-quoted string starting at
// `i` (where source[i] == quote). Handles backslash escapes. Returns
// the index AFTER the closing quote, or `end` if unterminated.
func skipString(source string, i int, quote byte, end int) int {
	i++ // consume opening quote
	for i < end {
		c := source[i]
		if c == '\\' && i+1 < end {
			i += 2
			continue
		}
		if c == quote {
			return i + 1
		}
		i++
	}
	return end
}

// skipTemplate moves past a backtick template literal starting at `i`.
// Honours nested `${...}` interpolations (which themselves can contain
// template literals) by counting brace depth inside `${...}`.
func skipTemplate(source string, i int, end int) int {
	i++ // consume opening backtick
	for i < end {
		c := source[i]
		if c == '\\' && i+1 < end {
			i += 2
			continue
		}
		if c == '`' {
			return i + 1
		}
		if c == '$' && i+1 < end && source[i+1] == '{' {
			// Walk to the matching '}' for the interpolation expression.
			d := 1
			i += 2
			for i < end && d > 0 {
				switch source[i] {
				case '"', '\'':
					i = skipString(source, i, source[i], end)
					continue
				case '`':
					i = skipTemplate(source, i, end)
					continue
				case '{':
					d++
				case '}':
					d--
				}
				i++
			}
			continue
		}
		i++
	}
	return end
}

// scanPromptInjection fires on the string-concat-into-prompt anti-
// pattern: `const prompt = "..." + userQuestion;`. Heuristic — false
// negatives are acceptable (the LLM pass picks them up) but we
// shouldn't fire on a SYSTEM_PROMPT constant.
func scanPromptInjection(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range promptConcatRe.FindAllStringIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		line := lineNumberAt(source, matchStart)
		matchedSpan := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "prompt-injection",
			Severity:    promptInjectionSeverity,
			Title:       "User input concatenated into LLM prompt",
			Explanation: "A prompt-shaped variable is being built by concatenating a string literal with a value that almost certainly came from the caller. The model has no structural way to distinguish your instruction from the user's content — they're both just text. Keep the instruction in the system-role message and put untrusted input in a separate user-role message.",
			ContentHash: hashAiAppFinding(relPath, line, "prompt-injection", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-77",
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	return out
}

// scanUnsafeToolOutput fires on a shell/exec/SQL sink whose first arg
// references an LLM tool-output field. Runs two complementary regexes:
//
//   unsafeToolOutputRe     — sink(tool.input.X)  (SDK-typed tool refs)
//   unsafeToolOutputArgsRe — sink(args.X)        (canonical exec(args)
//                                                  shape + SQL sinks)
//
// Dedupes by line — a single sink at line N fires once even if both
// regexes happen to match the same span.
func scanUnsafeToolOutput(relPath, source string) []Finding {
	var out []Finding
	seenLines := make(map[int]bool)
	emit := func(loc []int, title, explanation, cwe string) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			return
		}
		line := lineNumberAt(source, matchStart)
		if seenLines[line] {
			return
		}
		seenLines[line] = true
		matchedSpan := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-tool-output",
			Severity:    unsafeToolOutputSeverity,
			Title:       title,
			Explanation: explanation,
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-tool-output", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         cwe,
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	for _, loc := range unsafeToolOutputRe.FindAllStringIndex(source, -1) {
		emit(loc,
			"LLM tool output flows directly into shell sink",
			"A shell or eval sink is being called with a value that came from an LLM tool call (tool.input.*, block.input.*, etc.). An attacker who controls the model output via prompt injection upstream gets arbitrary command execution on the host. Route the tool field through a fixed allowlist (tag → vetted command) before any shell/eval call.",
			"CWE-78",
		)
	}
	for _, loc := range unsafeToolOutputArgsRe.FindAllStringIndex(source, -1) {
		matched := source[loc[0]:loc[1]]
		// 0.5.3 precision improvement: skip when an allowlist guard
		// (`if (!ALLOWLIST.has(args.X))`) precedes the sink within the
		// same function. We scan backward ~30 lines for the guard
		// pattern on the SAME args.X field referenced by the sink.
		if precededByAllowlistGuard(source, loc[0], matched) {
			continue
		}
		cwe := "CWE-78"
		title := "LLM tool input flows directly into shell/SQL sink"
		explanation := "A tool-callable function takes user-supplied input as `args.X` and passes it unsanitized into a shell, eval, or raw-SQL sink. Because the SDK lets the model decide what to pass as args, any prompt injection upstream becomes arbitrary command/SQL execution. Route args through a fixed allowlist or use parameterized queries before reaching the sink."
		if strings.Contains(matched, "sql.") || strings.Contains(matched, "db.") || strings.Contains(matched, "pool.") || strings.Contains(matched, "client.") {
			cwe = "CWE-89"
			title = "LLM tool input flows directly into raw-SQL sink"
			explanation = "A tool-callable function takes user-supplied input as `args.X` and passes it into a raw SQL execution path (sql.unsafe, db.prepare, pool.unsafe, etc.). These bypass parameterization. Because the model decides args.X, prompt injection upstream becomes SQL injection. Use parameterized queries (sql`select ... ${value}`) or a table-allowlist read path."
		}
		emit(loc, title, explanation, cwe)
	}
	return out
}

// precededByAllowlistGuard returns true when a `Set.has(args.X)`-style
// allowlist check on the SAME args field appears within ~30 lines
// above pos. Used to suppress the args.X-into-sink finding when the
// pattern is allowlist-gated. Conservative: only suppresses if the
// args field name matches exactly.
func precededByAllowlistGuard(source string, pos int, sinkMatch string) bool {
	// Find the args.<field> reference in the sink match.
	argFieldRe := regexp.MustCompile(`\bargs\.(\w+)`)
	m := argFieldRe.FindStringSubmatch(sinkMatch)
	if len(m) < 2 {
		return false
	}
	argField := m[1]
	// Scan ~30 lines backward.
	start := pos
	lineCount := 0
	for start > 0 && lineCount < 30 {
		start--
		if source[start] == '\n' {
			lineCount++
		}
	}
	if start < 0 {
		start = 0
	}
	window := source[start:pos]
	// Look for an allowlist .has(args.<field>) check on the same field.
	for _, g := range allowlistGuardRe.FindAllStringSubmatch(window, -1) {
		if len(g) >= 2 && g[1] == argField {
			return true
		}
	}
	return false
}

// scanPublicEnvKey — 0.5.3 addition.
// SvelteKit / Astro / Nuxt shape of NEXT_PUBLIC_-style key exposure:
// `import { PUBLIC_X_API_KEY } from '$env/static/public'`. The existing
// clientLlmKeyRe matches process.env.* shapes only; this one catches
// the destructured-import shape.
func scanPublicEnvKey(relPath, source string) []Finding {
	var out []Finding
	seen := make(map[int]bool)
	for _, loc := range publicEnvKeyRe.FindAllStringSubmatchIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		line := lineNumberAt(source, matchStart)
		if seen[line] {
			continue
		}
		seen[line] = true
		matchedSpan := source[loc[2]:loc[3]] // capture group 1: the var name
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "client-side-llm-key",
			Severity:    clientLlmKeySeverity,
			Title:       "LLM provider key exposed via $env/static/public",
			Explanation: "A PUBLIC_-prefixed LLM provider env var is imported from SvelteKit's `$env/static/public` (also applies to Astro/Nuxt with the same prefix contract). PUBLIC_ vars are physically inlined into the client bundle at build time — once shipped, the key is published. Move the key to the private channel (`$env/static/private`) and proxy the upstream API call through a server endpoint.",
			ContentHash: hashAiAppFinding(relPath, line, "client-side-llm-key", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-798",
			OWASP:       "A02",
			Detection:   "regex",
		})
	}
	return out
}

// scanKeyInResponseSvelte — 0.5.3 addition.
// SvelteKit / generic shape: a `json({apiKey: <bare ident>_API_KEY})`
// response. process.env access doesn't appear; the env var was
// destructured from `$env/static/private` at import time, then handed
// straight back through the response. Same effect as the existing
// keyInResponseRe — categorised under client-side-llm-key.
func scanKeyInResponseSvelte(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range keyInResponseSvelteRe.FindAllStringIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		span := source[loc[0]:loc[1]]
		// Skip if the response body explicitly references process.env —
		// that's keyInResponseRe's domain, avoid double-firing.
		if strings.Contains(span, "process.env.") {
			continue
		}
		line := lineNumberAt(source, matchStart)
		// Point at the line of the bare identifier (the actual leak).
		identMatchRe := regexp.MustCompile(`(?:apiKey|api_key|secret|token|key)\s*:\s*[A-Z][A-Z0-9_]*(?:_API_KEY|_KEY|_TOKEN|_SECRET)\b`)
		if idx := identMatchRe.FindStringIndex(span); len(idx) == 2 {
			line = lineNumberAt(source, matchStart+idx[0])
		}
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "client-side-llm-key",
			Severity:    clientLlmKeySeverity,
			Title:       "Server route returns LLM provider key in response body",
			Explanation: "A route handler returns an LLM provider API key (imported via destructuring from $env/static/private or a similar pattern) in its JSON response body. Anyone who can reach the endpoint can read the key. Refactor so the route proxies the upstream API call instead of returning the credential.",
			ContentHash: hashAiAppFinding(relPath, line, "client-side-llm-key", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-522",
			OWASP:       "A02",
			Detection:   "regex",
		})
	}
	return out
}

// scanSvelteHtmlSink — 0.5.3 addition.
// `{@html X}` is Svelte's directive for rendering raw HTML, equivalent
// to React's dangerouslySetInnerHTML. When X is built from tool/
// assistant content (e.g. marked.parse() of LLM output), it's an XSS
// sink for attacker-influenced text. Categorised under unsafe-tool-
// output. Gated by a context check — must find a marked.parse / role
// / messages reference within ±40 lines so static-content @html calls
// don't fire.
func scanSvelteHtmlSink(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range svelteHtmlSinkRe.FindAllStringIndex(source, -1) {
		matchStart := loc[0]
		// Context check: marked.parse / role / messages / tool ref in
		// a ±40 line window.
		windowStart := matchStart
		windowEnd := loc[1]
		linesBack := 0
		for windowStart > 0 && linesBack < 40 {
			windowStart--
			if source[windowStart] == '\n' {
				linesBack++
			}
		}
		linesFwd := 0
		for windowEnd < len(source) && linesFwd < 40 {
			if source[windowEnd] == '\n' {
				linesFwd++
			}
			windowEnd++
		}
		window := source[windowStart:windowEnd]
		if !svelteHtmlContextRe.MatchString(window) {
			continue
		}
		line := lineNumberAt(source, matchStart)
		matchedSpan := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-tool-output",
			Severity:    unsafeToolOutputSeverity,
			Title:       "Svelte {@html ...} renders LLM-influenced content without sanitization",
			Explanation: "Svelte's {@html ...} directive renders raw HTML — the equivalent of React's dangerouslySetInnerHTML. When the value comes from marked.parse() of tool/assistant content (or any LLM-influenced source), attacker-controllable HTML reaches the DOM. CWE-79. Pass the content through a sanitizer (e.g. DOMPurify) before rendering, or render as plain text.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-tool-output", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-79",
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	return out
}

// scanAnthropicSystemMerge — 0.5.3 addition.
// Anthropic's SDK takes the system prompt as a top-level `system:`
// parameter (not as a `role: 'system'` message inside messages[]).
// The existing scanUnsafeRoleMerge cannot see this shape. Two cases:
//
//   1. Inline template: `messages.create({system: \`${x}\`, ...})`
//      — fires immediately on anthropicSystemParamRe.
//
//   2. Indirect identifier: `messages.create({system: systemPrompt})`
//      where `systemPrompt` was assigned a template-literal-with-
//      interpolation earlier in the same file. Catches the canonical
//      `const systemPrompt = \`${baseSystem}\n${userInput}\`` shape.
func scanAnthropicSystemMerge(relPath, source string) []Finding {
	var out []Finding
	seen := make(map[int]bool)
	// Case 1: inline template literal in the system: parameter.
	for _, loc := range anthropicSystemParamRe.FindAllStringIndex(source, -1) {
		if inNonCodeContext(source, loc[0]) {
			continue
		}
		// Position the finding at the line where `system:` appears.
		matchSpan := source[loc[0]:loc[1]]
		sysIdx := strings.Index(matchSpan, "system")
		line := lineNumberAt(source, loc[0])
		if sysIdx >= 0 {
			line = lineNumberAt(source, loc[0]+sysIdx)
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		matchedSpan := matchSpan
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "Anthropic system: parameter contains template-literal interpolation",
			Explanation: "Anthropic's messages.create / messages.stream takes a top-level `system:` parameter that the model treats with operator authority — the structural equivalent of OpenAI's `role: 'system'` message. Interpolating user-controllable values into the system parameter is the same vulnerability under a different SDK shape. Keep system content static; route variable inputs through the user role.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-1039",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	// Case 2: indirect identifier — `system: systemPrompt` where
	// systemPrompt was built from a template literal earlier.
	// Build a set of variable names assigned to template-literal
	// interpolation patterns.
	tmplVars := make(map[string]bool)
	for _, m := range templateConcatAssignedRe.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			tmplVars[m[1]] = true
		}
	}
	for _, m := range systemTernaryAssignedRe.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			tmplVars[m[1]] = true
		}
	}
	for _, loc := range anthropicSystemParamIdentRe.FindAllStringSubmatchIndex(source, -1) {
		if inNonCodeContext(source, loc[0]) {
			continue
		}
		// Capture group 1 spans loc[2]:loc[3].
		if loc[2] < 0 || loc[3] < 0 {
			continue
		}
		ident := source[loc[2]:loc[3]]
		if !tmplVars[ident] {
			continue
		}
		// Position at the `system:` line within the matched span.
		matchSpan := source[loc[0]:loc[1]]
		sysIdx := strings.Index(matchSpan, "system")
		line := lineNumberAt(source, loc[0])
		if sysIdx >= 0 {
			line = lineNumberAt(source, loc[0]+sysIdx)
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "Anthropic system: parameter built from template-literal concat",
			Explanation: "Anthropic's `system:` parameter is assigned a variable that was built from a template literal with `${...}` interpolation. The interpolated value reaches the operator channel where the model treats it with elevated authority. Keep system content static; route variable inputs through the user role.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", source[loc[0]:loc[1]]),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-1039",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanAnthropicUnboundedStream — 0.5.3 addition.
// Anthropic's streaming uses a method call (`anthropic.messages.stream(`)
// rather than OpenAI's `stream: true` property. The existing
// scanUnboundedStream only matches `stream: true`. This detector
// catches the Anthropic shape with the same abort-in-scope gate.
func scanAnthropicUnboundedStream(relPath, source string) []Finding {
	var out []Finding
	seen := make(map[int]bool)
	for _, loc := range anthropicStreamCallRe.FindAllStringIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		// Same abort-in-scope gate as scanUnboundedStream — if there's
		// an AbortController / signal: / .abort( in the surrounding
		// window, treat as bounded.
		windowStart := matchStart
		windowEnd := loc[1]
		linesBack := 0
		for windowStart > 0 && linesBack < 20 {
			windowStart--
			if source[windowStart] == '\n' {
				linesBack++
			}
		}
		linesFwd := 0
		for windowEnd < len(source) && linesFwd < 20 {
			if source[windowEnd] == '\n' {
				linesFwd++
			}
			windowEnd++
		}
		window := source[windowStart:windowEnd]
		if abortInScopeRe.MatchString(window) {
			continue
		}
		line := lineNumberAt(source, matchStart)
		if seen[line] {
			continue
		}
		seen[line] = true
		matchedSpan := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unbounded-stream",
			Severity:    unboundedStreamSeverity,
			Title:       "Anthropic messages.stream() call without abort handling",
			Explanation: "An Anthropic streaming call (anthropic.messages.stream) has no AbortController or `signal:` parameter in its surrounding scope. If the client disconnects or the model hangs, the request keeps a worker slot occupied and continues billing tokens. Pass `signal: controller.signal` and abort the controller on the request's abort event (request.signal.addEventListener('abort', ...)).",
			ContentHash: hashAiAppFinding(relPath, line, "unbounded-stream", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-770",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanUnboundedFetch — 0.5.4 addition.
// Catches `fetch(<arg with args.X>, ...)` calls that omit the
// `signal:` option in their opts object. Used to detect tool-side
// streaming-fetch patterns where an attacker-controlled URL can pin
// a long-lived connection that the agent loop reads via for-await.
// CWE-770 (uncontrolled resource consumption).
func scanUnboundedFetch(relPath, source string) []Finding {
	var out []Finding
	seen := make(map[int]bool)
	for _, loc := range unboundedFetchRe.FindAllStringIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		// Find the matching close-paren for this fetch( call so we can
		// check whether signal: appears anywhere in the call. Naive
		// paren-balancing — sufficient for the common cases. Bail at
		// 500 chars to avoid quadratic blowup on giant calls.
		depth := 0
		end := matchStart
		for i := matchStart; i < len(source) && i < matchStart+500; i++ {
			if source[i] == '(' {
				depth++
			} else if source[i] == ')' {
				depth--
				if depth == 0 {
					end = i + 1
					break
				}
			}
		}
		callBody := source[loc[0]:end]
		if signalInFetchOptsRe.MatchString(callBody) {
			continue
		}
		line := lineNumberAt(source, matchStart)
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unbounded-stream",
			Severity:    unboundedStreamSeverity,
			Title:       "fetch() without signal: option, URL from tool args",
			Explanation: "An LLM tool-callable function passes `args.url` (or another args.X field) to `fetch(...)` without a `signal:` AbortController option. An attacker-controlled URL can point at a slow endpoint and pin the agent's network read indefinitely, holding tokens and a worker slot. Pass `signal: controller.signal` and abort the controller on a timeout / disconnect.",
			ContentHash: hashAiAppFinding(relPath, line, "unbounded-stream", source[loc[0]:loc[1]]),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-770",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanHtmlKeyEmbed — 0.5.4 addition.
// Catches server-rendered HTML that embeds an LLM provider API key
// as a template-literal substitution inside a res.send(`<...>`) call.
// Semantically equivalent to NEXT_PUBLIC_-style client exposure but
// hidden behind server-rendered HTML.
func scanHtmlKeyEmbed(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range htmlKeyEmbedRe.FindAllStringIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		span := source[loc[0]:loc[1]]
		// Point at the line of the actual leak (the process.env.X line)
		// rather than the containing res.send keyword.
		offsetWithinMatch := strings.Index(span, "process.env.")
		line := lineNumberAt(source, matchStart)
		if offsetWithinMatch > 0 {
			line = lineNumberAt(source, matchStart+offsetWithinMatch)
		}
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "client-side-llm-key",
			Severity:    clientLlmKeySeverity,
			Title:       "Server-rendered HTML embeds LLM provider key",
			Explanation: "A `res.send` call embeds `process.env.X_API_KEY` (or similar) into a backtick-quoted HTML template that ships to the browser. The key reaches the page DOM as an attribute or text node — semantically the same exposure as NEXT_PUBLIC_, hidden behind server-rendered HTML. Anyone who loads the page reads the key via view-source. Refactor so the upstream provider call happens server-side and the response (not the credential) ships to the client.",
			ContentHash: hashAiAppFinding(relPath, line, "client-side-llm-key", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-522",
			OWASP:       "A02",
			Detection:   "regex",
		})
	}
	return out
}

// scanKeyInResponse fires on a server route that returns an LLM
// provider API key inside the JSON response body. The leak shape is
// semantically equivalent to shipping the key in the client bundle —
// it hides behind a server endpoint instead of inlining into the bundle.
// Categorised under client-side-llm-key since the effect is identical
// (key reaches the browser).
func scanKeyInResponse(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range keyInResponseRe.FindAllStringIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		span := source[loc[0]:loc[1]]
		// Point the finding at the line of the actual leak (the
		// `apiKey: process.env.X_API_KEY` line) rather than the
		// containing Response.json/res.json keyword.
		offsetWithinMatch := strings.Index(span, "process.env.")
		line := lineNumberAt(source, matchStart)
		if offsetWithinMatch > 0 {
			line = lineNumberAt(source, matchStart+offsetWithinMatch)
		}
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "client-side-llm-key",
			Severity:    clientLlmKeySeverity,
			Title:       "Server route returns LLM provider key in response body",
			Explanation: "A route handler returns a process.env.*_API_KEY (or *_TOKEN / *_SECRET) value in its JSON response. Anyone who can reach the endpoint can read the key — the route is functionally a public credential dispenser. Even with auth gating, a single bug in the auth check exposes the key. Refactor so the route proxies the upstream API call instead of returning the credential.",
			ContentHash: hashAiAppFinding(relPath, line, "client-side-llm-key", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-522",
			OWASP:       "A02",
			Detection:   "regex",
		})
	}
	return out
}

// ── Helpers (ported from workers/src/security/llm-app.ts) ────────

// lineNumberAt returns the 1-based line containing position pos. O(pos)
// — fine for the prefilter sizes; the regex itself is the cost driver.
func lineNumberAt(source string, pos int) int {
	if pos > len(source) {
		pos = len(source)
	}
	return strings.Count(source[:pos], "\n") + 1
}

// inNonCodeContext is true when the match sits inside a comment or a
// string literal — same shape as the hosted helper. Filters the doc-
// example + changelog + JSDoc false positives the hosted side already
// learned about, plus matches embedded inside test-description strings
// (`it("flags role: 'system' ...", ...)`).
//
// Walks back from `pos` to the start of the line counting unescaped
// quote toggles. If at `pos` we're inside an unterminated `"...` or
// `'...` quote on this line, treat as non-code. Template-literal `\``
// is handled by the adjacent-char check (the common case is matches
// at the start of a template body) and by callers that explicitly
// pre-filter `\`\`\` doc blocks at the source level.
func inNonCodeContext(source string, pos int) bool {
	if pos < 0 || pos > len(source) {
		return false
	}
	lineStart := strings.LastIndexByte(source[:pos], '\n') + 1 // 0 if no newline
	before := strings.TrimLeft(source[lineStart:pos], " \t")
	if strings.HasPrefix(before, "//") || strings.HasPrefix(before, "*") {
		return true
	}
	if pos == 0 {
		return false
	}
	prev := source[pos-1]
	if prev == '"' || prev == '\'' || prev == '`' {
		return true
	}
	// Walk back to lineStart, counting unescaped " and ' opens. Either
	// count odd → match sits inside a string literal on this line.
	var dq, sq int
	for i := lineStart; i < pos; i++ {
		c := source[i]
		if c == '\\' && i+1 < pos {
			i++ // skip the escaped char
			continue
		}
		switch c {
		case '"':
			if sq%2 == 0 { // only counts if not inside a single-quoted string
				dq++
			}
		case '\'':
			if dq%2 == 0 {
				sq++
			}
		}
	}
	return dq%2 == 1 || sq%2 == 1
}

func extractLine(source string, line1Based int) string {
	if line1Based < 1 {
		return ""
	}
	lines := strings.Split(source, "\n")
	if line1Based > len(lines) {
		return ""
	}
	return lines[line1Based-1]
}

// hashAiAppFinding mirrors the secrets pass content-hash shape so the
// dedup downstream (sastlocal vs prefilter) keeps the regex hit when
// the LLM finds the same shape — the regex pass is the source of truth
// when both agree.
func hashAiAppFinding(filePath string, line int, category, span string) string {
	return hashFinding(filePath, strconv.Itoa(line), category, span)
}
