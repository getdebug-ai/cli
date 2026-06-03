// Patcher: open-redirect (CWE-601).
//
// Port of workers/src/fix/patchers/open-redirect.ts. Redirecting to a
// user-controlled URL without validation lets an attacker craft a link
// like `/login?next=https://evil.com` and bounce users off-site after
// auth. A real multi-domain allowlist needs a config the patcher can't
// see — but the most common safe fallback ("only redirect to same-
// origin relative paths") is a tight inline check that needs no helper.
//
//   res.redirect(url)
//     → res.redirect((typeof url === "string" && url.startsWith("/") &&
//                     !url.startsWith("//")) ? url : "/")
//
// The guard rejects undefined/null shapes, protocol-relative URLs, and
// absolute URLs; falls through to "/" which is always same-origin.
//
// Edge cases the v1 deliberately skips (decline with reason):
//   - The redirect argument is itself a function call — Go's regexp has
//     no balanced-paren support, and a flat regex over `arg` could match
//     something we shouldn't.
//   - Multiple .redirect(...) calls on one line.
//   - Non-JS/TS — Python's redirect would need a multi-statement guard.

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

// Match <callable>.redirect(<simple-arg>). The arg is restricted to
// identifier chains + bracket/literal access (`url`, `req.query.next`,
// `body["target"]`) — anything that's a single expression with no nested
// function calls or parens. A function-call arg won't match and the
// patcher will defer cleanly.
//
// Capture groups: 1 = callable chain, 2 = argument expression.
var jsRedirectRe = regexp.MustCompile(`\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.redirect\s*\(\s*([A-Za-z_$][\w$.\[\]'"]*)\s*\)`)

// OpenRedirectPatcher wraps the redirect target in a same-origin path
// guard. Reads `arg` four times — safe because the regex rules out
// function calls (no side effects in identifier-chain expressions).
func OpenRedirectPatcher(in PatcherInput) PatcherResult {
	lines := strings.Split(in.Source, "\n")
	idx := in.Match.LineStart - 1
	if idx < 0 || idx >= len(lines) {
		return PatcherResult{Reason: "lineStart out of range — file likely changed since scan"}
	}

	original := lines[idx]
	replacements := 0
	patched := jsRedirectRe.ReplaceAllStringFunc(original, func(m string) string {
		sub := jsRedirectRe.FindStringSubmatch(m)
		callable, arg := sub[1], sub[2]
		replacements++
		return fmt.Sprintf(
			`%s.redirect((typeof %s === "string" && %s.startsWith("/") && !%s.startsWith("//")) ? %s : "/")`,
			callable, arg, arg, arg, arg,
		)
	})

	if replacements == 0 {
		return PatcherResult{
			Reason: fmt.Sprintf(
				"line %d no longer contains a simple .redirect(arg) call — file may have drifted, or the argument is a function call / complex expression the v1 patcher doesn't handle",
				in.Match.LineStart,
			),
		}
	}
	if replacements > 1 {
		return PatcherResult{
			Reason: fmt.Sprintf("line %d has multiple .redirect(...) calls — manual fix recommended", in.Match.LineStart),
		}
	}

	out := strings.Join(append(append(append([]string{}, lines[:idx]...), patched), lines[idx+1:]...), "\n")
	desc := strings.Join([]string{
		fmt.Sprintf("Wrapped the redirect target on line %d in a same-origin path guard.", in.Match.LineStart),
		"Only relative paths (`/…`) pass; protocol-relative URLs (`//evil.com/…`) and",
		"absolute URLs are rejected and fall through to `/`. This closes CWE-601 for the",
		"common case.",
		"",
		"If this redirect needs to land on a different trusted origin (e.g. a sibling",
		"subdomain after SSO), replace the inline check with an explicit allowlist —",
		"compare the candidate's parsed `URL.host` against a known-good set, not a",
		"string-prefix on the path.",
	}, "\n")

	return PatcherResult{OK: true, Patched: out, Description: desc}
}
