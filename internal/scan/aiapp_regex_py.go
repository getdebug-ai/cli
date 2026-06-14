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
//
// FIX 3 (2026-06-06 crewAI dogfood): `message` and `query` were in the
// identifier set so the regex fired on `self.message = f"{cause}"` in
// every custom Exception subclass and on `query = "SELECT ... " + table`
// in any SQL builder — 14 of the 22 HIGH false positives on a 1,217-file
// Python repo came from this single pair. Neither identifier is
// idiomatic for prompt construction (LLM SDKs use `prompt`,
// `system_prompt`, `user_prompt`; the rest of the allowlist covers
// common variants). Dropped from both regexes; tests in
// aiapp_regex_py_test.go pin the exception/SQL shapes as non-firing.
var promptConcatPyRe = regexp.MustCompile(
	`(?s)\b(prompt|full_prompt|system_prompt|user_prompt|final_prompt|complete_prompt|combined_prompt)\s*=\s*["'][^"']*["']\s*\+\s*[a-zA-Z_]`,
)
var promptFStringPyRe = regexp.MustCompile(
	`(?s)\b(prompt|full_prompt|system_prompt|user_prompt|final_prompt|complete_prompt|combined_prompt)\s*=\s*f["'][^"']*\{[a-zA-Z_]`,
)

// ── unbounded-stream (Python) ───────────────────────────────────
//
// `stream=True` kwarg on an LLM call. The Python SDKs return an
// iterator that holds the HTTP connection open; without a `with`
// context manager or explicit `.close()` / `.cancel()` in the
// surrounding scope, a disconnecting client leaks the connection.
//
// FIX 4 (2026-06-06 crewAI dogfood): require kwarg context. The
// previous `\bstream\s*=\s*True\b` matched attribute assignments
// (`self.stream = True`) and bare variable bindings (`stream = True`),
// plus docstring example text — 9 of the medium FPs on crewAI came
// from this single shape. Kwarg form requires the identifier to sit
// immediately after `(` or `,` (with optional whitespace), so:
//   client.chat.completions.create(stream=True, ...)  ← matches
//   func(arg, stream=True)                            ← matches
//   self.stream = True                                ← does NOT match
//   stream = True                                     ← does NOT match
var streamTruePyRe = regexp.MustCompile(`[(,]\s*stream\s*=\s*True\b`)

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
	// 0.5.5 — Tier C cycle 4 (cst-fastapi-tools) FastAPI/async detector wave.
	// The pre-existing prefilters above only catch the `stream=True` kwarg
	// shape and `tool_call.input.X`-style tool sinks. FastAPI's streaming
	// surface (StreamingResponse generators, SSE, websockets, httpx,
	// BackgroundTasks) plus the Pydantic-param tool shape, dynamic message
	// roles, persona-file role injection, key-in-response and RAG-concat
	// patterns were all structurally invisible. These nine close the gap.
	out = append(out, scanPyStreamNoGuard(relPath, source)...)
	out = append(out, scanPyHttpxStreamNoTimeout(relPath, source)...)
	out = append(out, scanPyShellToolArg(relPath, source)...)
	out = append(out, scanPySqlFString(relPath, source)...)
	out = append(out, scanPyDynamicRole(relPath, source)...)
	out = append(out, scanPyPersonaPathRole(relPath, source)...)
	out = append(out, scanPyKeyInResponse(relPath, source)...)
	out = append(out, scanPyRagConcat(relPath, source)...)
	out = append(out, scanPyRowIntoPrompt(relPath, source)...)
	// 0.5.6 — Tier C cycle 5 (cst-crewai-multiagent) CrewAI URM wave. An
	// agent's backstory/goal IS its system prompt and its role is its
	// authority; CrewAI expresses both as constructor kwargs the dict-shape
	// role detectors never inspect. These three reach the Agent() surface.
	out = append(out, scanPyCrewBackstoryInterp(relPath, source)...)
	out = append(out, scanPyCrewBackstoryFile(relPath, source)...)
	out = append(out, scanPyCrewAgentRole(relPath, source)...)
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

// ── 0.5.5 FastAPI / async detector wave ─────────────────────────

var (
	pyAsyncDefRe = regexp.MustCompile(`(?m)^[ \t]*async def \w+`)
	// Streaming signal inside a function body: an LLM `stream=True` kwarg
	// or a websocket receive loop. `StreamingResponse(` is deliberately
	// NOT a trigger — the route wrapper that returns StreamingResponse of
	// a *guarded* generator (chat_stream_safe) would otherwise false-fire.
	pyStreamTriggerRe = regexp.MustCompile(`[(,]\s*stream\s*=\s*True\b|websocket\.receive_text\s*\(`)
	// Bounding/cleanup guards. Presence of any one (as real code, after
	// comment+docstring stripping) means the stream is handled.
	pyStreamGuardRe = regexp.MustCompile(`is_disconnected|WebSocketDisconnect|asyncio\.timeout|\bfinally\s*:`)

	pyHttpxClientRe = regexp.MustCompile(`httpx\.AsyncClient\s*\(([^)]*)\)`)
	pyHttpxStreamRe = regexp.MustCompile(`\.stream\s*\(`)

	pyShellSinkRe = regexp.MustCompile(`(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen)\s*\(`)

	pySqlFStringRe = regexp.MustCompile(`\b(?:execute|executemany|executescript)\s*\(\s*f["']`)

	// A message role taken from a bare identifier rather than a quoted
	// literal — i.e. the role is variable, attacker-influenceable.
	pyDynamicRoleRe  = regexp.MustCompile(`["']role["']\s*:\s*[a-zA-Z_]\w*`)
	pyRoleAllowlistRe = regexp.MustCompile(`ALLOWED_ROLES|allowed_roles|VALID_ROLES|valid_roles`)

	// open(f"...{...}") — interpolated path = traversal vector.
	pyOpenFStringRe   = regexp.MustCompile(`\bopen\s*\(\s*f["'][^"']*\{`)
	pySystemRoleLitRe = regexp.MustCompile(`["']role["']\s*:\s*["']system["']`)

	// A credential field in a returned/serialized dict mapped to a real
	// key source (settings.*key*, an *_KEY/*_SECRET constant, os.environ).
	pyKeyInResponseRe = regexp.MustCompile(`["'](?:api_?key|apikey|api_secret|secret_key|openai_api_key|anthropic_api_key)["']\s*:\s*(?:settings\.[a-zA-Z_]*key[a-zA-Z_]*|[A-Z][A-Z0-9_]*(?:KEY|SECRET)|os\.environ)`)

	// A prompt-shaped variable built by concatenating a `.join(...)` of
	// retrieved chunks — indirect (RAG) prompt injection.
	pyRagConcatRe = regexp.MustCompile(`\b(?:prompt|context|full_prompt|system_prompt|user_prompt|final_prompt|augmented|grounding)\s*=\s*[^\n]*\+[^\n]*\.join\s*\(`)

	// An f-string that interpolates a full DB-row-shaped variable into a
	// prompt — every column (PII included) flows to the model.
	pyRowIntoPromptRe = regexp.MustCompile(`f["'][^"']*\{(?:profile_row|customer_row|db_row|user_row|account_row|profile|customer|record)\}`)
)

// pyStrippedLines returns source split into lines with Python comments and
// triple-quoted docstring bodies removed, so structural checks (guard
// presence, triggers) don't trip on prose that merely *names* a construct.
// The returned slice is line-aligned with strings.Split(source, "\n").
func pyStrippedLines(source string) []string {
	docLines := pythonDocstringLines([]byte(source))
	raw := strings.Split(source, "\n")
	out := make([]string, len(raw))
	for i, line := range raw {
		if docLines[i+1] { // pythonDocstringLines is 1-based
			out[i] = ""
			continue
		}
		if h := indexOfUnquotedHash(line); h >= 0 {
			out[i] = line[:h]
		} else {
			out[i] = line
		}
	}
	return out
}

func pyLeadingSpaces(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

// scanPyStreamNoGuard flags an `async def` whose body opens an LLM stream
// (stream=True) or a websocket receive loop but contains no disconnect
// check, no finally cleanup, and no asyncio.timeout bound. Function-scoped
// by indentation; checks run on the comment/docstring-stripped body so the
// fixtures' own explanatory comments don't false-suppress. CWE-400.
func scanPyStreamNoGuard(relPath, source string) []Finding {
	raw := strings.Split(source, "\n")
	stripped := pyStrippedLines(source)
	var out []Finding
	for i := range raw {
		if !pyAsyncDefRe.MatchString(raw[i]) {
			continue
		}
		indent := pyLeadingSpaces(raw[i])
		end := len(raw)
		for j := i + 1; j < len(raw); j++ {
			if strings.TrimSpace(stripped[j]) == "" {
				continue
			}
			if pyLeadingSpaces(raw[j]) <= indent {
				end = j
				break
			}
		}
		body := strings.Join(stripped[i:end], "\n")
		if !pyStreamTriggerRe.MatchString(body) {
			continue
		}
		if pyStreamGuardRe.MatchString(body) {
			continue
		}
		line := i + 1
		span := strings.TrimSpace(raw[i])
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unbounded-stream",
			Severity:    unboundedStreamSeverity,
			Title:       "Streaming handler without disconnect or cleanup guard",
			Explanation: "This async handler opens an LLM stream (or a websocket receive loop) but never checks `request.is_disconnected()`, has no `finally:` to close the upstream, and sets no `asyncio.timeout` bound. If the client disconnects or the model stalls, the coroutine keeps a worker (and the upstream connection) pinned and continues billing tokens. Poll `is_disconnected()` and release the stream in a `finally:` (or wrap it in `asyncio.timeout`).",
			ContentHash: hashAiAppFinding(relPath, line, "unbounded-stream", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-400",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyHttpxStreamNoTimeout flags an httpx.AsyncClient constructed without
// a timeout= in a file that streams off it (.stream(...)). httpx defaults
// to no read timeout, so a slow-loris upstream holds the streaming socket
// open indefinitely. CWE-770.
func scanPyHttpxStreamNoTimeout(relPath, source string) []Finding {
	if !pyHttpxStreamRe.MatchString(source) {
		return nil
	}
	var out []Finding
	for _, loc := range pyHttpxClientRe.FindAllStringSubmatchIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		args := source[loc[2]:loc[3]]
		if strings.Contains(args, "timeout") {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unbounded-stream",
			Severity:    unboundedStreamSeverity,
			Title:       "httpx streaming client built without a timeout",
			Explanation: "httpx.AsyncClient() is constructed with no `timeout=` and then used to `.stream(...)`. httpx's default for a client built this way leaves the streaming read without an idle/total cap, so a stalled upstream holds this coroutine and its socket open forever. Pass `timeout=httpx.Timeout(...)` (or a float) when constructing the client.",
			ContentHash: hashAiAppFinding(relPath, line, "unbounded-stream", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-770",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyShellToolArg flags a shell/exec sink invoked with shell=True (or the
// always-shell os.system / os.popen), the canonical shape for an LLM tool
// endpoint that runs a model-supplied command. CWE-78.
func scanPyShellToolArg(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range pyShellSinkRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		sink := source[loc[0]:loc[1]]
		alwaysShell := strings.HasPrefix(sink, "os.system") || strings.HasPrefix(sink, "os.popen")
		end := findCallEndPy(source, loc[1])
		callBody := source[loc[1]:end]
		if !alwaysShell && !strings.Contains(callBody, "shell=True") {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := sink
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-tool-output",
			Severity:    unsafeToolOutputSeverity,
			Title:       "LLM tool argument executed through the shell",
			Explanation: "A shell sink (subprocess with shell=True, or os.system/os.popen) runs a value that an agent tool endpoint takes straight from the model's tool-call payload. A prompt-injection upstream becomes arbitrary command execution on the host. Drop shell=True and pass an argv list, or map the tool field through a fixed allowlist before executing.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-tool-output", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-78",
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	return out
}

// scanPySqlFString flags a DB cursor execute() whose SQL is an f-string —
// the value (often an LLM tool arg) is formatted into the query text instead
// of bound as a parameter. CWE-89.
func scanPySqlFString(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range pySqlFStringRe.FindAllStringIndex(source, -1) {
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
			Title:       "SQL built with an f-string instead of a bound parameter",
			Explanation: "An execute() call is passed an f-string SQL literal, so interpolated values (commonly an LLM tool argument) become part of the query structure — SQL injection. Use a parameterized query: `execute(\"... WHERE id = ?\", (value,))`.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-tool-output", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-89",
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyDynamicRole flags a chat message whose `role` is a bare identifier
// (a request-supplied variable) rather than a quoted literal — a caller can
// set role="system" and escalate a user turn. Suppressed when the file
// validates the role against an allowlist. CWE-863.
func scanPyDynamicRole(relPath, source string) []Finding {
	if pyRoleAllowlistRe.MatchString(source) {
		return nil
	}
	var out []Finding
	for _, loc := range pyDynamicRoleRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		// Skip attribute-access role values — {"role": message.role},
		// {"role": self.role} — that's the message object's OWN role field, a
		// controlled value, not a request-supplied variable. Only a bare
		// identifier ({"role": role_input}) signals a request-derived role.
		if loc[1] < len(source) && source[loc[1]] == '.' {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "Message role taken from an unvalidated variable",
			Explanation: "A chat message's `role` is assigned from a variable that traces back to request input, with no allowlist. A caller can submit role=\"system\" and have their content treated with operator authority. Validate the role against a fixed set ({\"user\",\"assistant\"}) before building the message, and never let a request choose the system role.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-863",
			OWASP:       "A01",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyPersonaPathRole flags open(f"...{var}...") (an interpolated, hence
// traversable, file path) in a file that pins file contents as a system
// role — path traversal plus role escalation. CWE-22 + CWE-863.
func scanPyPersonaPathRole(relPath, source string) []Finding {
	if !pySystemRoleLitRe.MatchString(source) {
		return nil
	}
	var out []Finding
	for _, loc := range pyOpenFStringRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "System-role content loaded from an interpolated file path",
			Explanation: "A file path is built by interpolating a variable into open(f\"...\"), and the file's contents are pinned as a `system` role message. The path is traversable (`../`) and the loaded text is trusted as an operator instruction — path traversal and role escalation in one step. Resolve the name against a fixed allowlist of persona files and never feed arbitrary file contents into the system role.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-22",
			OWASP:       "A01",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyKeyInResponse flags a credential field in a returned/serialized dict
// mapped to a real key source — the provider key leaks in an API response.
// CWE-200.
func scanPyKeyInResponse(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range pyKeyInResponseRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "client-side-llm-key",
			Severity:    clientLlmKeySeverity,
			Title:       "Provider API key serialized into a response body",
			Explanation: "A dict that is returned from a route (or otherwise serialized to a client) maps an api_key/secret field to the live provider key. Anyone who can reach the endpoint reads the credential out of the JSON. Never include the key in a response payload; expose only non-secret config (model name, limits).",
			ContentHash: hashAiAppFinding(relPath, line, "client-side-llm-key", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-200",
			OWASP:       "A01",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyRagConcat flags a prompt-shaped variable assembled by concatenating
// a `.join(...)` of retrieved chunks straight into the prompt text — indirect
// (RAG) prompt injection with no provenance boundary. CWE-77.
func scanPyRagConcat(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range pyRagConcatRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "prompt-injection",
			Severity:    promptInjectionSeverity,
			Title:       "Retrieved chunks concatenated into the prompt without a boundary",
			Explanation: "Document chunks pulled from a store are `.join`-ed straight into the prompt string with no role separator or provenance marker. A poisoned document reads to the model as trusted context and can smuggle instructions (indirect prompt injection). Keep retrieved content in a clearly-delimited block and never merge it with the instruction text.",
			ContentHash: hashAiAppFinding(relPath, line, "prompt-injection", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-77",
			OWASP:       "A03",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyRowIntoPrompt flags an f-string that interpolates a full DB-row
// variable into a prompt — every column the SELECT returned (PII included)
// is sent to the model. CWE-359.
func scanPyRowIntoPrompt(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range pyRowIntoPromptRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "pii-in-prompt",
			Severity:    piiInPromptSeverity,
			Title:       "Full database row interpolated into a prompt",
			Explanation: "An f-string drops a whole DB row (the result of a `SELECT *`) into the prompt, so every column — email, phone, address, tokens — is sent to the provider and may land in their logs/retention. Project only the fields the task needs before building the prompt.",
			ContentHash: hashAiAppFinding(relPath, line, "pii-in-prompt", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-359",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// ── 0.5.6 CrewAI URM detectors ──────────────────────────────────

var (
	// Gate for ALL CrewAI URM detectors: only run them in files that actually
	// use CrewAI. The role=/backstory=/goal= patterns below are far too common
	// in general Python (any `role=<var>` kwarg — e.g. `role = None`,
	// `role = getattr(msg, "role")`) to fire safely without this. Without the
	// gate they produced 4 false positives on simonw/llm, which has no CrewAI
	// at all.
	pyCrewAIMarkerRe = regexp.MustCompile(`(?i)\bcrewai\b`)
	// backstory= / goal= assigned an interpolated f-string. In CrewAI the
	// backstory is the agent's system prompt; an f-string here merges
	// caller/agent-controlled text into the operator channel.
	pyCrewBackstoryInterpRe = regexp.MustCompile(`\b(?:backstory|goal)\s*=\s*f["'][^"']*\{`)
	// backstory= / goal= loaded from a file (often a traversable path).
	pyCrewBackstoryFileRe = regexp.MustCompile(`\b(?:backstory|goal)\s*=\s*open\s*\(`)
	// A CrewAI Agent role kwarg assigned a bare identifier (a variable that
	// traces to request input) rather than a quoted literal.
	pyCrewAgentRoleRe = regexp.MustCompile(`\brole\s*=\s*[a-zA-Z_]\w*`)
)

// scanPyCrewBackstoryInterp flags an Agent backstory/goal built by f-string
// interpolation — untrusted text reaching the agent's system prompt.
// Suppressed when the file gates roles/inputs through an allowlist. CWE-1039.
func scanPyCrewBackstoryInterp(relPath, source string) []Finding {
	if !pyCrewAIMarkerRe.MatchString(source) || pyRoleAllowlistRe.MatchString(source) {
		return nil
	}
	var out []Finding
	for _, loc := range pyCrewBackstoryInterpRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "Agent backstory/goal built from interpolated text",
			Explanation: "A CrewAI Agent's `backstory` (or `goal`) is its system prompt. Interpolating a variable into it via f-string merges caller- or upstream-agent-controlled text into the operator channel, where the model treats it with elevated authority — the agent-framework form of unsafe role merge. Keep the backstory static and pass variable inputs as Task descriptions, not into the agent's identity.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-1039",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyCrewBackstoryFile flags an Agent backstory/goal loaded from a file —
// the file's contents become the agent's system prompt, and an interpolated
// path is traversable. CWE-22.
func scanPyCrewBackstoryFile(relPath, source string) []Finding {
	if !pyCrewAIMarkerRe.MatchString(source) {
		return nil
	}
	var out []Finding
	for _, loc := range pyCrewBackstoryFileRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "Agent backstory loaded from a file",
			Explanation: "A CrewAI Agent's backstory (its system prompt) is read from a file with open(). If the path is interpolated it is traversable, and the file's contents are trusted as operator-level instructions. Resolve persona files against a fixed allowlist and never feed arbitrary file contents into an agent's identity.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-22",
			OWASP:       "A01",
			Detection:   "regex",
		})
	}
	return out
}

// scanPyCrewAgentRole flags a CrewAI Agent whose role kwarg is a bare
// identifier (a request-derived variable) rather than a quoted literal —
// the caller chooses the agent's authority. Suppressed under an allowlist.
// CWE-863.
func scanPyCrewAgentRole(relPath, source string) []Finding {
	if !pyCrewAIMarkerRe.MatchString(source) || pyRoleAllowlistRe.MatchString(source) {
		return nil
	}
	var out []Finding
	for _, loc := range pyCrewAgentRoleRe.FindAllStringIndex(source, -1) {
		if inNonCodeContextPython(source, loc[0]) {
			continue
		}
		line := lineNumberAt(source, loc[0])
		span := source[loc[0]:loc[1]]
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unsafe-role-merge",
			Severity:    unsafeRoleMergeSeverity,
			Title:       "CrewAI Agent role taken from an unvalidated variable",
			Explanation: "A CrewAI Agent's `role` kwarg is assigned from a variable that traces back to request input, with no allowlist. The role drives the agent's authority and delegation reach, so a caller can pick a privileged role and escalate. Validate the role against a fixed set before constructing the agent.",
			ContentHash: hashAiAppFinding(relPath, line, "unsafe-role-merge", span),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-863",
			OWASP:       "A01",
			Detection:   "regex",
		})
	}
	return out
}

// findCallEndPy returns the index just past the matching close paren for a
// call whose opening paren is at start-1 (i.e. start points just after `(`).
// Naive paren-balancing that skips string literals; caps the scan so a
// malformed source can't run away.
func findCallEndPy(source string, start int) int {
	depth := 1
	const maxScan = 2000
	end := start + maxScan
	if end > len(source) {
		end = len(source)
	}
	for i := start; i < end; i++ {
		switch source[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		case '"', '\'':
			i = skipString(source, i+1, source[i], end)
		}
	}
	return end
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

// pythonDocstringLines returns the set of 1-indexed line numbers that
// fall inside Python triple-quoted strings (`"""…"""` / `'''…'''`).
// Crude state machine: doesn't recognise raw-string prefixes (`r"""`) or
// backslash escapes inside the body — neither matters for the
// suppression use case. False classification of a single line just
// falls back to default scanner behaviour.
//
// Lines that OPEN or CLOSE a triple are included — the surrounding
// columns may be code, but the trigger patterns this function gates
// (PEM-block markers, see scanContent FIX 2) never appear in code
// outside a string literal anyway.
func pythonDocstringLines(content []byte) map[int]bool {
	out := map[int]bool{}
	src := content
	inside := false
	var quote byte
	line := 1
	i := 0
	for i < len(src) {
		if src[i] == '\n' {
			line++
			i++
			continue
		}
		// Triple-quote token.
		if i+3 <= len(src) {
			c := src[i]
			if (c == '"' || c == '\'') && src[i+1] == c && src[i+2] == c {
				if !inside {
					inside = true
					quote = c
					out[line] = true
				} else if c == quote {
					inside = false
					out[line] = true
				}
				i += 3
				continue
			}
		}
		if inside {
			out[line] = true
		}
		i++
	}
	return out
}

// isPythonDoctestLine reports whether a line's leftmost non-whitespace
// prefix is the `>>> ` doctest marker (or a `... ` continuation). Lines
// matching are documentation examples — never real credentials.
func isPythonDoctestLine(line string) bool {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i+3 < len(line) && line[i] == '>' && line[i+1] == '>' && line[i+2] == '>' && line[i+3] == ' ' {
		return true
	}
	if i+3 < len(line) && line[i] == '.' && line[i+1] == '.' && line[i+2] == '.' && line[i+3] == ' ' {
		return true
	}
	return false
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


