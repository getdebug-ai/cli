// Ruby AI-app regex prefilters — v0.5.8 (Tier C cycle 7, cst-rails).
//
// The corpus's fourth language. Rails AI apps express the six AI-app
// categories through Ruby idioms no Python/JS/Go regex touches: "...#{x}"
// string interpolation, `messages = [{ role: params[:role] }]`, backtick
// command execution, File.read("personas/#{name}.txt"), user.to_json, and
// ActionController::Live streaming. Gated on an LLM-SDK marker (rbLlmMarkerRe)
// so non-AI Ruby produces nothing.

package scan

import (
	"regexp"
)

var (
	rbLlmMarkerRe = regexp.MustCompile(`(?i)openai|anthropic|langchain|ruby-openai|\bllm\b|\bassistant\b|\bagent\b|actioncontroller::live|chat\(\s*parameters|stream_proc|tool_call`)
	// Real `request_timeout:`/`=` config (not the word in a comment).
	rbRequestTimeoutRe = regexp.MustCompile(`request_timeout\s*[:=]`)
	// A real `ensure` block (line-anchored), not the word "ensure" in a comment.
	rbEnsureRe = regexp.MustCompile(`(?m)^\s*ensure\b`)

	// A prompt/system-named var assigned a string with #{...} interpolation.
	rbPromptInterpRe = regexp.MustCompile(`\b\w*(?:prompt|system)\w*\s*=\s*"[^"]*#\{`)
	// A prompt-named var concatenated from a .join of chunks.
	rbPromptJoinRe = regexp.MustCompile(`\b\w*prompt\w*\s*=\s*"[^"]*"\s*\+[^\n]*\.join\(`)

	// A `role: "system"` hash entry whose content string interpolates input.
	rbSystemInterpRe = regexp.MustCompile(`role:\s*["']system["'][^}\n]*content:\s*["'][^"']*#\{`)
	// A message role taken from params[...] or a bare variable.
	rbDynamicRoleRe = regexp.MustCompile(`\brole:\s*(?:@?\w+\[|@?[a-z]\w*\s*[,}])`)
	// Allowlist marker that suppresses the dynamic-role finding.
	rbRoleAllowlistRe = regexp.MustCompile(`ALLOWED_ROLES|allowed_roles`)
	// A system/persona string read from an interpolated (traversable) path.
	rbReadFileInterpRe = regexp.MustCompile(`File\.read\(\s*"[^"]*#\{`)

	// A credential field in a rendered hash mapped to ENV[...] or a key attr.
	rbKeyInResponseRe = regexp.MustCompile(`\bapi_key:\s*(?:ENV\[|\w+\.\w*[Kk]ey)`)

	// Backtick command execution with interpolation.
	rbBacktickExecRe = regexp.MustCompile("`[^`]*#\\{")
	// system("sh","-c",...) — explicit shell invocation.
	rbExecShellRe = regexp.MustCompile(`system\(\s*"(?:sh|bash)"\s*,\s*"-c"`)
	// SQL built by string interpolation through connection.execute.
	rbSqlInterpRe = regexp.MustCompile(`\.execute\(\s*"[^"]*#\{`)

	// A user-shape object serialized with .to_json (full record into prompt).
	rbToJsonUserRe = regexp.MustCompile(`\b(?:user|profile|customer|account|record|current_user)\.to_json`)
	// A full ActiveRecord .attributes hash interpolated into a string.
	rbAttributesRe = regexp.MustCompile(`#\{\s*(?:profile|user|customer|record)\.attributes`)

	// A streaming chat call with a stream: proc/lambda. Suppressed when a
	// request_timeout is configured in the file.
	rbStreamProcRe = regexp.MustCompile(`stream:\s*(?:proc\b|lambda\b|->|\w*_?proc\b)`)
	// ActionController::Live stream write. Suppressed when the file closes
	// the stream (a bounded / ensure-guarded handler).
	rbLiveStreamWriteRe = regexp.MustCompile(`response\.stream\.write`)
)

// inRubyCommentLine reports whether pos sits on a line whose first non-space
// character is `#` (a full-line Ruby comment). Unlike a full string-literal
// tokenizer this deliberately does NOT treat string interiors as non-code,
// because several Ruby detectors match interpolation *inside* a string.
func inRubyCommentLine(source string, pos int) bool {
	start := 0
	for i := pos - 1; i >= 0; i-- {
		if source[i] == '\n' {
			start = i + 1
			break
		}
	}
	i := start
	for i < pos && (source[i] == ' ' || source[i] == '\t') {
		i++
	}
	return i < len(source) && source[i] == '#' && (i+1 >= len(source) || source[i+1] != '{')
}

// scanAiAppRegexRuby runs the Ruby AI-app prefilters, gated on an LLM-SDK
// marker so non-AI Ruby files produce nothing.
func scanAiAppRegexRuby(relPath, source string) []Finding {
	if !rbLlmMarkerRe.MatchString(source) {
		return nil
	}
	var out []Finding
	emit := func(re *regexp.Regexp, cat, sev, cwe, owasp, title, expl string) {
		for _, loc := range re.FindAllStringIndex(source, -1) {
			if inRubyCommentLine(source, loc[0]) {
				continue
			}
			line := lineNumberAt(source, loc[0])
			span := source[loc[0]:loc[1]]
			out = append(out, Finding{
				FilePath:    relPath,
				LineStart:   line,
				LineEnd:     line,
				Category:    cat,
				Severity:    sev,
				Title:       title,
				Explanation: expl,
				ContentHash: hashAiAppFinding(relPath, line, cat, span),
				Snippet:     extractLine(source, line),
				CWE:         cwe,
				OWASP:       owasp,
				Detection:   "regex",
			})
		}
	}

	emit(rbPromptInterpRe, "prompt-injection", promptInjectionSeverity, "CWE-77", "A03",
		"Prompt built with string interpolation from request input",
		"A prompt- or system-named string is built with Ruby #{...} interpolation, splicing values that almost certainly came from the request into the instruction. The model can't separate your instruction from the user's content. Keep the instruction static and pass untrusted input as a separate user-role message.")
	emit(rbPromptJoinRe, "prompt-injection", promptInjectionSeverity, "CWE-77", "A03",
		"Retrieved chunks concatenated into the prompt",
		"Document chunks are .join'd straight into the prompt with no provenance boundary. A poisoned document reads to the model as trusted context (indirect prompt injection). Keep retrieved content in a clearly delimited block, separate from the instruction.")
	emit(rbSystemInterpRe, "unsafe-role-merge", unsafeRoleMergeSeverity, "CWE-1039", "A04",
		"User input interpolated into a system-role message",
		"A `{ role: \"system\", content: \"...#{x}...\" }` message interpolates a variable into the system channel, where the model treats it with operator authority. Keep system content static; route variable inputs through the user role.")
	emit(rbReadFileInterpRe, "unsafe-role-merge", unsafeRoleMergeSeverity, "CWE-22", "A01",
		"System content read from an interpolated file path",
		"A file path is built with File.read(\"...#{x}...\") and its contents are used as the system/persona instruction. The path is traversable and the loaded text is trusted as operator authority. Resolve names against a fixed allowlist.")
	emit(rbKeyInResponseRe, "client-side-llm-key", clientLlmKeySeverity, "CWE-200", "A01",
		"Provider API key serialized into a response",
		"A rendered hash maps an api_key field to ENV[...] or a key attribute. Any caller reading the endpoint gets the credential. Never include the key in a response payload.")
	emit(rbBacktickExecRe, "unsafe-tool-output", unsafeToolOutputSeverity, "CWE-78", "A03",
		"LLM tool argument executed via backticks",
		"An agent tool runs a backtick command literal with #{...} interpolation of a value from the model's tool-call payload. A prompt-injection upstream becomes arbitrary command execution. Avoid the shell; use an argv form with a fixed allowlist.")
	emit(rbExecShellRe, "unsafe-tool-output", unsafeToolOutputSeverity, "CWE-78", "A03",
		"LLM tool argument run through system(\"sh\", \"-c\", ...)",
		"An agent tool shells out with system(\"sh\", \"-c\", ...) on a model-supplied argument. Drop the shell; pass an argv list and map the tool field through a fixed allowlist.")
	emit(rbSqlInterpRe, "unsafe-tool-output", unsafeToolOutputSeverity, "CWE-89", "A03",
		"SQL built with string interpolation",
		"connection.execute is passed a string with #{...} interpolation, so the value (often an LLM tool argument) becomes part of the query structure — SQL injection. Use a bound parameter: exec_query(\"... WHERE id = ?\", \"q\", [id]).")
	emit(rbToJsonUserRe, "pii-in-prompt", piiInPromptSeverity, "CWE-359", "A04",
		"User record serialized into an LLM prompt",
		"user.to_json (or profile/customer.to_json) serializes every column — email, phone, SSN — into the prompt, sending it to the provider's logs/retention. Project only the fields the task needs before serializing.")
	emit(rbAttributesRe, "pii-in-prompt", piiInPromptSeverity, "CWE-359", "A04",
		"Full ActiveRecord attributes interpolated into a prompt",
		"A model's full .attributes hash is interpolated into the prompt, so every column (PII included) is sent to the model. Project to the needed fields before building the prompt.")
	emit(rbLiveStreamWrite(source), "unbounded-stream", unboundedStreamSeverity, "CWE-400", "A04",
		"ActionController::Live stream written without a cleanup guard",
		"response.stream.write runs in a loop with no `ensure response.stream.close` and no client-disconnect check. A client that goes away leaves the action looping and the connection open. Close the stream in an ensure block and break on disconnect.")

	// Streaming proc with no request_timeout configured in the file.
	if !rbRequestTimeoutRe.MatchString(source) {
		emit(rbStreamProcRe, "unbounded-stream", unboundedStreamSeverity, "CWE-400", "A04",
			"Streaming chat call with no request timeout",
			"A streaming chat call passes a stream: proc but the OpenAI::Client was built with no request_timeout, so a stalled upstream pins the calling thread indefinitely. Configure request_timeout on the client (or a wall-clock deadline on the loop).")
	}

	// Dynamic message role — suppressed when the file validates against an
	// allowlist.
	if !rbRoleAllowlistRe.MatchString(source) {
		emit(rbDynamicRoleRe, "unsafe-role-merge", unsafeRoleMergeSeverity, "CWE-863", "A01",
			"Message role taken from an unvalidated source",
			"A chat message's role is taken from params[...] or a bare variable with no allowlist. A caller can submit role=\"system\" and have their content treated with operator authority. Validate the role against a fixed set before building the message.")
	}
	return out
}

// rbLiveStreamWrite returns the stream-write detector, or a never-matching
// regex when the file already closes the stream (a bounded handler).
func rbLiveStreamWrite(source string) *regexp.Regexp {
	if rbEnsureRe.MatchString(source) {
		return regexpNeverMatch
	}
	return rbLiveStreamWriteRe
}

// regexpNeverMatch matches nothing (a `\z\A`-style impossible anchor pair).
var regexpNeverMatch = regexp.MustCompile(`\z.\A`)
