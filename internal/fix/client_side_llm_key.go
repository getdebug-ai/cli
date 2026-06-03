// Patcher: client-side-llm-key (CWE-798).
//
// Port of workers/src/fix/patchers/client-side-llm-key.ts. Strips the
// build-time public prefix from the matched env var name and leaves a
// three-line comment above pointing the dev at the real fix (move the
// LLM call to a server route).
//
// We deliberately DON'T try to auto-generate a server route or rewrite
// the caller — those are framework-specific and a wrong guess would
// break the app worse than leaving the work to the dev. The renamed
// env var without a server route fails LOUD at runtime (the env value
// won't exist server-side), which is the right failure mode: the bug
// surfaces immediately when the PR is tested instead of silently
// shipping with the key still exposed.
//
// Example:
//   process.env.NEXT_PUBLIC_OPENAI_API_KEY
// becomes:
//   // getdebug: removed NEXT_PUBLIC_ prefix — this key must only be
//   // read from a server route. See docs.getdebug.dev/fixes/client-llm-key
//   process.env.OPENAI_API_KEY

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

// Build-time public prefixes — must match the detector's regex so we
// know what to strip. Keep in sync with workers/src/security/llm-app.ts.
var publicPrefixes = []string{"NEXT_PUBLIC_", "VITE_", "EXPO_PUBLIC_", "REACT_APP_", "PUBLIC_"}

// Leading indentation extractor — preserves tabs/spaces verbatim so
// inserted comments visually match surrounding code.
var leadingWsRe = regexp.MustCompile(`^[\t ]*`)

// ClientSideLlmKeyPatcher rewrites a single public-prefixed env var
// reference and prepends a three-line explainer comment. The matched
// span must be present at the matched line — drift declines cleanly.
func ClientSideLlmKeyPatcher(in PatcherInput) PatcherResult {
	lines := strings.Split(in.Source, "\n")
	idx := in.Match.LineStart - 1
	if idx < 0 || idx >= len(lines) {
		return PatcherResult{Reason: "lineStart out of range — file likely changed since scan"}
	}

	if in.Match.MatchedSpan == "" {
		return PatcherResult{Reason: "match has no MatchedSpan — patcher needs the exact env-var token to rewrite"}
	}

	var prefix string
	for _, p := range publicPrefixes {
		if strings.HasPrefix(in.Match.MatchedSpan, p) {
			prefix = p
			break
		}
	}
	if prefix == "" {
		return PatcherResult{
			Reason: fmt.Sprintf(`matched span %q doesn't start with a known public prefix`, in.Match.MatchedSpan),
		}
	}

	original := lines[idx]
	if !strings.Contains(original, in.Match.MatchedSpan) {
		return PatcherResult{
			Reason: fmt.Sprintf("matched span not present at line %d — file likely drifted", in.Match.LineStart),
		}
	}

	renamed := strings.TrimPrefix(in.Match.MatchedSpan, prefix)
	patchedLine := strings.Replace(original, in.Match.MatchedSpan, renamed, 1)
	indent := leadingWsRe.FindString(original)
	commentLines := []string{
		fmt.Sprintf("%s// getdebug: removed %s prefix — this key must only be read from a server route.", indent, prefix),
		fmt.Sprintf("%s// Move the LLM call to a server endpoint (Next.js route handler / server action)", indent),
		fmt.Sprintf("%s// so the renamed env var is read server-side only. https://docs.getdebug.dev/fixes/client-llm-key", indent),
	}

	out := make([]string, 0, len(lines)+3)
	out = append(out, lines[:idx]...)
	out = append(out, commentLines...)
	out = append(out, patchedLine)
	out = append(out, lines[idx+1:]...)

	return PatcherResult{
		OK:          true,
		Patched:     strings.Join(out, "\n"),
		Description: fmt.Sprintf("Renamed env var by stripping the `%s` prefix and added a comment pointing at the server-side fix. The renamed var will be undefined in the client bundle, forcing the LLM call to move server-side.", prefix),
	}
}
