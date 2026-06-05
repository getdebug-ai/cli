// Python AI-app regex prefilters — v0.4.0.
//
// Mirror of the JS/TS prefilters in aiapp_regex.go, ported to Python
// idioms. Covers 5 of the 6 AI-app categories — client-side-llm-key
// is omitted because Python is generally server-side and doesn't have
// the framework-public-prefix bundle-leak vector that NEXT_PUBLIC_ /
// VITE_ / EXPO_PUBLIC_ create on the JS side. Streamlit / Gradio apps
// have a different leak surface; if a Python-specific framework
// pattern emerges, add it here.
//
// All five patterns hit on common Python LLM SDK conventions:
//   - openai / openai-python
//   - anthropic / anthropic-python
//   - langchain
//   - litellm
//   - the common `messages=[{"role": "system", "content": "..."}]` shape
//
// Each pattern targets the conventional shape — anything actively
// trying to evade (renamed vars, custom wrappers) will miss. The
// LLM SAST pass closes the gap.

package scan

import (
	"regexp"
	"strings"
)

// ── pii-in-prompt (Python) ──────────────────────────────────────
//
// Triggers on `json.dumps(<user-shape>)` or `str(<user-shape>)`
// where the name is in the curated allowlist AND an LLM-call marker
// is within ±20 lines (re-uses the JS llmCallContextRe — markers like
// `messages=`, `chat.completions.create`, `messages.create` work in
// both languages).
var piiInPromptPyRe = regexp.MustCompile(
	`\b(?:json\.dumps|str|repr)\s*\(\s*(user|profile|account|customer|member|current_user|logged_in_user|user_info|user_data|user_profile|user_record|user_object|personal_info|personal_details)\b`,
)

// ── unsafe-role-merge (Python) ──────────────────────────────────
//
// {"role": "system", "content": f"..{var}.."}  — f-string interpolation
// inside a system-role message. Python uses double-OR-single quotes;
// the regex covers both.
var systemRoleMarkerPyRe = regexp.MustCompile(`["']role["']\s*:\s*["']system["']`)

// f-string OR concat interpolation inside a content field. f-strings
// are Python's template literals; `+` concat is the older form.
var contentInterpolatedPyRe = regexp.MustCompile(
	`["']content["']\s*:\s*(?:f["'][^"']*\{[^}]+\}[^"']*["']|["'][^"']*["']\s*\+\s*[a-zA-Z_])`,
)

// ── prompt-injection (Python) ───────────────────────────────────
//
// `prompt = "You are a translator. " + user_input` OR
// `prompt = f"You are a translator. {user_input}"`
// Variable-name allowlist matches the JS scanner. Multi-line via (?s).
var promptConcatPyRe = regexp.MustCompile(
	`(?s)\b(prompt|full_prompt|system_prompt|user_prompt|final_prompt|complete_prompt|combined_prompt|message|query)\s*=\s*["'][^"']*["']\s*\+\s*[a-zA-Z_]`,
)
var promptFStringPyRe = regexp.MustCompile(
	`(?s)\b(prompt|full_prompt|system_prompt|user_prompt|final_prompt|complete_prompt|combined_prompt|message|query)\s*=\s*f["'][^"']*\{[a-zA-Z_]`,
)

// ── unbounded-stream (Python) ───────────────────────────────────
//
// `stream=True` kwarg on an LLM call. The Python SDKs return an
// iterator that holds the HTTP connection open; without a `with`
// context manager or explicit `.close()` / `.cancel()` in the
// surrounding scope, a disconnecting client leaks the connection.
var streamTruePyRe = regexp.MustCompile(`\bstream\s*=\s*True\b`)

// Bounded-stream markers in the surrounding ±40-line scope: a `with`
// block, an explicit `.close()` / `.cancel()` call, or a `timeout=`
// kwarg on the same call.
var streamBoundPyRe = regexp.MustCompile(
	`\b(?:with\s+|\.close\s*\(|\.cancel\s*\(|timeout\s*=)`,
)

// ── unsafe-tool-output (Python) ─────────────────────────────────
//
// A shell/exec sink called with a tool-output reference as an arg.
// Python sinks: subprocess.{run,call,Popen,check_output}, os.system,
// os.popen, exec, eval, plus the `shell=True` keyword (which makes
// any of those shell-injectable). The tool-output shapes mirror the
// SDK conventions: tool_call.input.X, block.input.X, tool_use.input.X,
// etc.
var unsafeToolOutputPyRe = regexp.MustCompile(
	`\b(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen|exec|eval)\s*\(\s*[^)]*?\b(?:tool|tool_use|tool_call|block|tool_result|tool_output|message|response)\.(?:input|arguments|args|parameters|result|content)\.`,
)

// scanAiAppRegexPython applies the Python-specific prefilters to one
// .py source file. Composition mirrors scanAiAppRegexJS — every
// category gets its own scanner so unit tests can exercise them
// in isolation.
func scanAiAppRegexPython(relPath, source string) []Finding {
	var out []Finding
	out = append(out, scanPiiInPromptPython(relPath, source)...)
	out = append(out, scanUnsafeRoleMergePython(relPath, source)...)
	out = append(out, scanPromptInjectionPython(relPath, source)...)
	out = append(out, scanUnboundedStreamPython(relPath, source)...)
	out = append(out, scanUnsafeToolOutputPython(relPath, source)...)
	return out
}

func scanPiiInPromptPython(relPath, source string) []Finding {
	var out []Finding
	lines := strings.Split(source, "\n")
	for _, loc := range piiInPromptPyRe.FindAllStringSubmatchIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
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
		span := source[loc[2]:loc[3]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "pii-in-prompt",
			Severity:    piiInPromptSeverity,
			Title:       "User PII serialised into LLM prompt",
			Explanation: "json.dumps / str / repr on a user-shape variable inside an LLM call sends every field — email, phone, address, DOB — to the provider's logs and may end up in their retention/training pipeline. Reduce the payload to the fields the task actually needs before serialising, or pull out just the display fields at the call site.",
			ContentHash: hashAiAppFinding(relPath, line, "pii-in-prompt", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-359",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

func scanUnsafeRoleMergePython(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range systemRoleMarkerPyRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		objectEnd := findObjectEnd(source, loc[1], 600)
		if objectEnd <= loc[1] {
			continue
		}
		window := source[loc[1]:objectEnd]
		ileft := contentInterpolatedPyRe.FindStringIndex(window)
		if ileft == nil {
			continue
		}
		matchAbs := loc[1] + ileft[0]
		line := lineNumberAt(source, matchAbs)
		span := window[ileft[0]:ileft[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "User-controlled string interpolated into system role",
			Explanation: "A `{\"role\": \"system\"}` message contains f-string / concat interpolation, suggesting user-controlled values are reaching the system channel. Models treat the system role with operator-level authority — letting untrusted text in there bypasses much of the safety training and prompt-injection mitigations. Keep system content static; route variable inputs through the user role.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-1039",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

func scanPromptInjectionPython(relPath, source string) []Finding {
	var out []Finding
	emit := func(loc []int) {
		if inNonCodeContextPython(source, loc[0]) {
			return
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "prompt-injection",
			Severity:    promptInjectionSeverity,
			Title:       "User input concatenated into LLM prompt",
			Explanation: "A prompt-shaped variable is being built by concatenating (or f-string-interpolating) a string literal with a value that almost certainly came from the caller. The model has no structural way to distinguish your instruction from the user's content. Keep the instruction in the system-role message and put untrusted input in a separate user-role message.",
			ContentHash: hashAiAppFinding(relPath, line, "prompt-injection", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-77",
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	for _, loc := range promptConcatPyRe.FindAllStringIndex(source, -1) {
		emit(loc)
	}
	for _, loc := range promptFStringPyRe.FindAllStringIndex(source, -1) {
		emit(loc)
	}
	return out
}

func scanUnboundedStreamPython(relPath, source string) []Finding {
	var out []Finding
	lines := strings.Split(source, "\n")
	for _, loc := range streamTruePyRe.FindAllStringIndex(source, -1) {
		pos := loc[0]
		if inNonCodeContextPython(source, pos) {
			continue
		}
		line := lineNumberAt(source, pos)
		from := line - 1 - 40
		if from < 0 {
			from = 0
		}
		to := line + 40
		if to > len(lines) {
			to = len(lines)
		}
		// Strip Python comments (`#` to end-of-line) from the window
		// before checking for bound-stream markers. Without this, a
		// comment like `# TODO: add timeout` would falsely satisfy
		// the bounded-stream check. Crude but correct for the common
		// case; the rare `#`-in-string-literal case stays a known
		// limitation worth living with.
		stripped := make([]string, 0, to-from)
		for _, raw := range lines[from:to] {
			if i := indexOfUnquotedHash(raw); i >= 0 {
				stripped = append(stripped, raw[:i])
			} else {
				stripped = append(stripped, raw)
			}
		}
		window := strings.Join(stripped, "\n")
		if streamBoundPyRe.MatchString(window) {
			continue
		}
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unbounded-stream",
			Severity:    unboundedStreamSeverity,
			Title:       "Streaming LLM call without abort handling",
			Explanation: "A streaming LLM call (stream=True) has no bounding scope (no `with` context manager, no `.close()` / `.cancel()`, no `timeout=`) within ±40 lines. If the client disconnects or the model hangs, the request keeps a worker slot occupied and continues billing tokens. Use a `with` block, explicit cancel, or pass `timeout=`.",
			ContentHash: hashAiAppFinding(relPath, line, "unbounded-stream", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-770",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

func scanUnsafeToolOutputPython(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range unsafeToolOutputPyRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-tool-output",
			Severity:    unsafeToolOutputSeverity,
			Title:       "LLM tool output flows directly into shell sink",
			Explanation: "A shell or eval sink (subprocess / os.system / os.popen / exec / eval) is being called with a value that came from an LLM tool call (tool_call.input.*, block.input.*, etc.). An attacker who controls the model output via prompt injection upstream gets arbitrary command execution on the host. Route the tool field through a fixed allowlist (tag → vetted command) before any shell/eval call.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-tool-output", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-78",
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	return out
}

// indexOfUnquotedHash returns the index of the first `#` on the line
// that's not inside a quoted string, or -1 if the line is comment-
// free. Tracks the same dq/sq toggle the inNonCodeContext check uses;
// f-string prefix doesn't change the quoting (Python uses the same
// `"`/`'` delimiters for f-strings). Skips escaped quotes.
func indexOfUnquotedHash(line string) int {
	var dq, sq int
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			i++
			continue
		}
		switch c {
		case '"':
			if sq%2 == 0 {
				dq++
			}
		case '\'':
			if dq%2 == 0 {
				sq++
			}
		case '#':
			if dq%2 == 0 && sq%2 == 0 {
				return i
			}
		}
	}
	return -1
}

// inNonCodeContextPython is the Python-specific comment / string-
// literal skip. Comments use `#`; string literals use ", ', f", f',
// and triple-quoted variants. We don't fully tokenise — same simple
// heuristic the JS version uses: comment-line start AND quote-toggle
// count back to the line start.
func inNonCodeContextPython(source string, pos int) bool {
	if pos < 0 || pos > len(source) {
		return false
	}
	lineStart := -1
	for i := pos - 1; i >= 0; i-- {
		if source[i] == '\n' {
			lineStart = i + 1
			break
		}
	}
	if lineStart < 0 {
		lineStart = 0
	}
	// Comment-line skip: trim leading whitespace, check for '#'.
	i := lineStart
	for i < pos && (source[i] == ' ' || source[i] == '\t') {
		i++
	}
	if i < pos && source[i] == '#' {
		return true
	}
	// In-line string-literal skip: count unescaped ", ' on this line.
	var dq, sq int
	for j := lineStart; j < pos; j++ {
		c := source[j]
		if c == '\\' && j+1 < pos {
			j++
			continue
		}
		switch c {
		case '"':
			if sq%2 == 0 {
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


