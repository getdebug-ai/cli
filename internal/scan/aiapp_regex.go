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
func ScanAiAppRegex(workdir string, logf func(format string, args ...any)) (*AiAppRegexResult, error) {
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
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
			// supported
		default:
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
		rel, err := filepath.Rel(workdir, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		res.FilesScanned++
		res.Findings = append(res.Findings, scanAiAppRegex(rel, string(raw))...)
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// scanAiAppRegex applies every prefilter to one file's source. Split
// out so unit tests can exercise the regexes without a workdir walk.
func scanAiAppRegex(relPath, source string) []Finding {
	var out []Finding
	out = append(out, scanClientSideLlmKey(relPath, source)...)
	out = append(out, scanUnboundedStream(relPath, source)...)
	out = append(out, scanPiiInPrompt(relPath, source)...)
	out = append(out, scanUnsafeRoleMerge(relPath, source)...)
	out = append(out, scanPromptInjection(relPath, source)...)
	out = append(out, scanUnsafeToolOutput(relPath, source)...)
	return out
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
		if !llmCallContextRe.MatchString(window) {
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

// scanUnsafeToolOutput fires on a shell/exec sink whose first arg
// references an LLM tool-output field. The safe variant routes the
// tool field through an allowlist before reaching the sink.
func scanUnsafeToolOutput(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range unsafeToolOutputRe.FindAllStringIndex(source, -1) {
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
			Category:    "unsafe-tool-output",
			Severity:    unsafeToolOutputSeverity,
			Title:       "LLM tool output flows directly into shell sink",
			Explanation: "A shell or eval sink is being called with a value that came from an LLM tool call (tool.input.*, block.input.*, etc.). An attacker who controls the model output via prompt injection upstream gets arbitrary command execution on the host. Route the tool field through a fixed allowlist (tag → vetted command) before any shell/eval call.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-tool-output", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-78",
			OWASP:       "A03",
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
