// Patcher: insecure-cors (CWE-942).
//
// Port of workers/src/fix/patchers/insecure-cors.ts. `Access-Control-
// Allow-Origin: *` instructs the browser to honor cross-origin reads
// from anywhere. A real allowlist requires the request's `Origin`
// header — pulling that off would need framework-aware code generation
// (Express vs Fastify vs Next.js vs edge), which the pure-function
// patcher contract doesn't model.
//
// What the v1 patcher does is narrower but still meaningful: swap the
// literal `"*"` value for a fail-closed env lookup so the wildcard is
// gone and the header is *off* by default until the dev configures
// CORS_ALLOWED_ORIGIN.
//
//   setHeader("Access-Control-Allow-Origin", "*")
//     → setHeader("Access-Control-Allow-Origin", (process.env.CORS_ALLOWED_ORIGIN ?? ""))
//
//   { "Access-Control-Allow-Origin": "*" }
//     → { "Access-Control-Allow-Origin": (process.env.CORS_ALLOWED_ORIGIN ?? "") }

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

// Match `"Access-Control-Allow-Origin"` (or single-quoted) followed by
// a `:` (object literal) or `,` (function arg pair), then `"*"`. We use
// backreference-equivalent grouping by capturing the key quote and value
// quote separately and asserting both quote groups match the same char
// in post-processing — Go's regexp has no backreference, so we accept
// any quote shape and rely on the post-match check to require equality.
//
// Capture groups: 1 = key quote, 2 = separator (with whitespace),
// 3 = value quote.
var jsCorsWildcardRe = regexp.MustCompile(`(["'])Access-Control-Allow-Origin(["'])(\s*[,:]\s*)(["'])\*(["'])`)

const jsCorsReplacementValue = `(process.env.CORS_ALLOWED_ORIGIN ?? "")`

// InsecureCorsPatcher rewrites a single wildcard Access-Control-Allow-
// Origin pair on the matched line to an env lookup that fails closed.
func InsecureCorsPatcher(in PatcherInput) PatcherResult {
	lines := strings.Split(in.Source, "\n")
	idx := in.Match.LineStart - 1
	if idx < 0 || idx >= len(lines) {
		return PatcherResult{Reason: "lineStart out of range — file likely changed since scan"}
	}

	original := lines[idx]
	replacements := 0
	patched := jsCorsWildcardRe.ReplaceAllStringFunc(original, func(m string) string {
		sub := jsCorsWildcardRe.FindStringSubmatch(m)
		// Go's regexp has no backreference. Enforce quote-symmetry on the
		// key and on the value here — if a real source line had mismatched
		// quotes for the same string literal, JS would have rejected it
		// long before the scanner ever saw it, so this is just a safety net.
		keyQ, keyQ2, sep, valQ1, valQ2 := sub[1], sub[2], sub[3], sub[4], sub[5]
		if keyQ != keyQ2 || valQ1 != valQ2 {
			return m
		}
		replacements++
		return fmt.Sprintf("%sAccess-Control-Allow-Origin%s%s%s", keyQ, keyQ, sep, jsCorsReplacementValue)
	})

	if replacements == 0 {
		return PatcherResult{
			Reason: fmt.Sprintf(
				"line %d no longer contains a wildcard Access-Control-Allow-Origin value — file may have drifted, the value may be in a non-literal shape (variable, template), or this is a config-file format the v1 patcher doesn't handle",
				in.Match.LineStart,
			),
		}
	}
	if replacements > 1 {
		return PatcherResult{
			Reason: fmt.Sprintf("line %d has multiple wildcard CORS pairs — manual fix recommended", in.Match.LineStart),
		}
	}

	out := strings.Join(append(append(append([]string{}, lines[:idx]...), patched), lines[idx+1:]...), "\n")
	desc := strings.Join([]string{
		fmt.Sprintf("Replaced wildcard Access-Control-Allow-Origin on line %d with a", in.Match.LineStart),
		`fail-closed env lookup (` + "`process.env.CORS_ALLOWED_ORIGIN ?? \"\"`" + `). The wildcard`,
		"is gone and CORS is now OFF until the env var is set — which closes CWE-942.",
		"",
		"Before merging, decide between two follow-ups:",
		"  (a) Single-origin: set CORS_ALLOWED_ORIGIN to the one trusted origin",
		"      (e.g. `https://app.example.com`) in every environment.",
		"  (b) Multi-origin: replace this line with a per-request allowlist check",
		"      against `req.headers.origin` — the env-fallback shape can't express",
		"      that, and a wrong allowlist is worse than no header.",
	}, "\n")

	return PatcherResult{OK: true, Patched: out, Description: desc}
}
