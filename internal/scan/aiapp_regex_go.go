// Go AI-app regex prefilters — v0.5.7 (Tier C cycle 6, cst-go-agent).
//
// The first non-Python/JS detector path in the corpus. Go AI apps express
// the same six AI-app categories through Go idioms the Python/JS regexes
// never touch: prompts built with fmt.Sprintf / strings.Join, the Anthropic
// `System:` field via anthropic.F(...), openai-go's ChatCompletionMessage
// {Role: ...} struct, os/exec tool sinks, json.Marshal of a user struct,
// and client.Messages.NewStreaming on a context.Background().
//
// The whole pass is gated on an LLM-SDK marker (goLlmMarkerRe): a .go file
// that doesn't talk to an LLM provider produces nothing, so ordinary Go
// services — including getdebug's own CLI — stay silent.

package scan

import (
	"regexp"
)

var (
	// Activation gate: only run on files that talk to an LLM provider.
	goLlmMarkerRe = regexp.MustCompile(`anthropic|openai|langchaingo|\bllms\.|api\.openai\.com|api\.anthropic\.com|/v1/messages|/v1/chat/completions`)

	// prompt-/system-named var assigned a fmt.Sprintf — interpolated prompt.
	goPromptSprintfRe = regexp.MustCompile(`\b\w*(?:[Pp]rompt|[Ss]ystem)\w*\s*:?=\s*fmt\.Sprintf\(`)
	// prompt-named var assembled by concatenating a strings.Join of chunks.
	goPromptJoinRe = regexp.MustCompile(`\b\w*(?:[Pp]rompt|[Aa]ugmented|[Gg]rounding|[Cc]ontext)\w*\s*:?=\s*"[^"]*"\s*\+[^\n]*strings\.Join\(`)

	// Anthropic System parameter built from a fmt.Sprintf (operator channel).
	goSystemInterpRe = regexp.MustCompile(`System:\s*(?:anthropic\.F\(\s*)?fmt\.Sprintf\(`)
	// A message Role assigned a bare identifier (not an SDK role constant,
	// which would be `openai.ChatMessageRole...` — i.e. followed by a dot).
	goDynamicRoleRe = regexp.MustCompile(`\bRole:\s*[a-z][a-zA-Z0-9_]*\s*[,}]`)
	// Allowlist marker that suppresses the dynamic-role finding. Anchored on
	// an `allowed*` assignment (real code) rather than the bare word, so a
	// comment that merely says "no allowlist" doesn't self-suppress.
	goRoleAllowlistRe = regexp.MustCompile(`\ballowed\w*\s*:?=|ALLOWED_ROLES|allowedRoles|validRoles`)
	// A system/persona string read from an interpolated (traversable) path.
	goReadFileInterpRe = regexp.MustCompile(`os\.ReadFile\(\s*fmt\.Sprintf\(`)

	// A credential field in an encoded/returned map mapped to a key source.
	goKeyInResponseRe = regexp.MustCompile(`["'](?:api_?key|apikey|api_secret|secret_key)["']\s*:\s*[\w.]+(?:[Kk]ey|[Ss]ecret)\b`)

	// os/exec sink invoked as a shell — the agent-tool command-injection shape.
	goExecShellRe = regexp.MustCompile(`exec\.Command\(\s*"(?:sh|bash|cmd|/bin/sh|/bin/bash)"\s*,\s*"(?:-c|/c)"`)
	// A DB call whose SQL is a fmt.Sprintf rather than a bound parameter.
	goSqlFmtRe = regexp.MustCompile(`\.(?:Query|QueryRow|Exec|QueryContext|ExecContext|QueryRowContext)\w*\(\s*fmt\.Sprintf\(`)

	// json.Marshal of a user-shape struct (full record into the prompt).
	goMarshalUserRe = regexp.MustCompile(`json\.Marshal\(\s*&?(?:user|userRecord|profile|customer|account|record)\b`)
	// A full row/struct formatted via %v/%+v into a prompt.
	goRowIntoPromptRe = regexp.MustCompile(`fmt\.Sprintf\([^)]*%\+?v[^)]*,\s*&?(?:profileRow|customerRow|customer|profile|record|row|userRecord)\b`)

	// Streaming opened on a non-cancellable context.Background().
	goStreamBackgroundRe = regexp.MustCompile(`NewStreaming\(\s*context\.Background\(\)`)
	// An http.Client built with no Timeout (empty struct literal).
	goHttpNoTimeoutRe = regexp.MustCompile(`&http\.Client\{\s*\}`)
)

// scanAiAppRegexGo runs the Go AI-app prefilters. Gated on an LLM-SDK marker
// so non-AI Go files produce nothing.
func scanAiAppRegexGo(relPath, source string) []Finding {
	if !goLlmMarkerRe.MatchString(source) {
		return nil
	}
	var out []Finding
	emit := func(re *regexp.Regexp, cat, sev, cwe, owasp, title, expl string) {
		for _, loc := range re.FindAllStringIndex(source, -1) {
			if inNonCodeContext(source, loc[0]) {
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

	emit(goPromptSprintfRe, "prompt-injection", promptInjectionSeverity, "CWE-77", "A03",
		"Prompt built with fmt.Sprintf from request input",
		"A prompt- or system-named string is assembled with fmt.Sprintf, interpolating values that almost certainly came from the caller. The model can't separate your instruction from the user's content. Keep the instruction static and pass untrusted input as a separate user-role message.")
	emit(goPromptJoinRe, "prompt-injection", promptInjectionSeverity, "CWE-77", "A03",
		"Retrieved chunks concatenated into the prompt",
		"Document chunks are strings.Join'd straight into the prompt with no provenance boundary. A poisoned document reads to the model as trusted context (indirect prompt injection). Keep retrieved content in a clearly delimited block, separate from the instruction.")
	emit(goSystemInterpRe, "unsafe-role-merge", unsafeRoleMergeSeverity, "CWE-1039", "A04",
		"Anthropic System parameter built from interpolated input",
		"The Anthropic `System:` parameter — the operator channel — is built with fmt.Sprintf, merging caller- or upstream-agent-controlled text into the role the model treats with elevated authority. Keep System static; route variable inputs through user-role messages.")
	emit(goReadFileInterpRe, "unsafe-role-merge", unsafeRoleMergeSeverity, "CWE-22", "A01",
		"System content read from an interpolated file path",
		"A file path is built by interpolating a variable into os.ReadFile(fmt.Sprintf(...)) and its contents are used as the system/persona instruction. The path is traversable and the loaded text is trusted as operator authority. Resolve names against a fixed allowlist.")
	emit(goKeyInResponseRe, "client-side-llm-key", clientLlmKeySeverity, "CWE-200", "A01",
		"Provider API key serialized into a response",
		"A response map maps an api_key/secret field to a key source (cfg.APIKey, *_KEY). Any caller reading the endpoint gets the credential. Never include the key in a response payload.")
	emit(goExecShellRe, "unsafe-tool-output", unsafeToolOutputSeverity, "CWE-78", "A03",
		"LLM tool argument executed through the shell",
		"An agent tool runs exec.Command(\"sh\", \"-c\", ...) on a value taken from the model's tool-call payload. A prompt-injection upstream becomes arbitrary command execution. Avoid the shell; pass an argv slice, or map the tool field through a fixed allowlist.")
	emit(goSqlFmtRe, "unsafe-tool-output", unsafeToolOutputSeverity, "CWE-89", "A03",
		"SQL built with fmt.Sprintf instead of a bound parameter",
		"A DB call is passed a fmt.Sprintf'd SQL string, so an interpolated value (often an LLM tool argument) becomes part of the query structure — SQL injection. Use placeholder parameters: db.Query(\"... WHERE id = $1\", id).")
	emit(goMarshalUserRe, "pii-in-prompt", piiInPromptSeverity, "CWE-359", "A04",
		"User record marshaled into an LLM prompt",
		"json.Marshal of a user-shape struct serializes every field — email, phone, SSN, address — into the prompt, sending it to the provider's logs/retention. Project only the fields the task needs before marshaling.")
	emit(goRowIntoPromptRe, "pii-in-prompt", piiInPromptSeverity, "CWE-359", "A04",
		"Full database row formatted into a prompt",
		"A whole DB row struct is formatted with %v/%+v into the prompt, so every column (PII included) is sent to the model. Project to the needed fields before building the prompt.")
	emit(goStreamBackgroundRe, "unbounded-stream", unboundedStreamSeverity, "CWE-400", "A04",
		"LLM stream opened on a non-cancellable context",
		"client.Messages.NewStreaming is opened on context.Background(), which carries no deadline and no cancellation. If the client disconnects or the model stalls, the stream goroutine is pinned and keeps billing. Derive a context.WithTimeout / WithCancel from the request and pass it in.")
	emit(goHttpNoTimeoutRe, "unbounded-stream", unboundedStreamSeverity, "CWE-770", "A04",
		"http.Client built without a timeout for streaming",
		"An &http.Client{} with no Timeout is used to stream an upstream LLM response. A response that never closes holds the connection and goroutine open indefinitely. Set a Timeout (or a per-request context deadline) on the client.")

	// Dynamic message role — suppressed when the file validates against an
	// allowlist.
	if !goRoleAllowlistRe.MatchString(source) {
		emit(goDynamicRoleRe, "unsafe-role-merge", unsafeRoleMergeSeverity, "CWE-863", "A01",
			"Message role taken from an unvalidated variable",
			"A chat message's Role is assigned from a bare variable that traces back to request input, with no allowlist. A caller can submit role=\"system\" and have their content treated with operator authority. Validate the role against a fixed set before building the message.")
	}
	return out
}
