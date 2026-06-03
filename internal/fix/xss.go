// Patcher: xss (CWE-79).
//
// Port of workers/src/fix/patchers/xss.ts. `element.innerHTML = userInput`
// parses the right-hand side as HTML, so anything resembling a <script>
// tag (or an inline event handler like <img onerror=…>) executes in the
// page's origin. The narrow safe fix when the dev's intent was "show this
// text" is `.textContent = userInput` — text is rendered verbatim, no
// parsing, no script execution.
//
//   el.innerHTML = userInput  →  el.textContent = userInput
//
// Behavior note: if the dev actually wanted to render HTML (server-
// rendered formatted message), the patch will display the markup as
// literal text. Strictly safer than the original — XSS is closed — but
// the dev needs to know they may need a sanitizer (DOMPurify, sanitize-
// html) instead. The description spells this out.
//
// Edge cases the v1 deliberately skips (decline with reason; finding
// still surfaces as explanation-only):
//   - `.innerHTML += x` (concatenation — different semantics)
//   - `.outerHTML = x` (replaces the element itself)
//   - `.insertAdjacentHTML(position, x)` (different API, position arg)
//   - Multiple `.innerHTML =` assignments on one line
//   - Reading `.innerHTML` (no `=`) — not a finding shape anyway

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

// Go's regexp has no negative lookahead — we accept `=` followed by
// anything-but-`=`, then re-emit the same trailing char. Captures:
// 1 = whitespace before `=`, 2 = whitespace/character after `=`.
//
// The trailing char is restored verbatim, so `el.innerHTML = x` becomes
// `el.textContent = x` (one space preserved either side). Compound
// assignments (`+=`, `|=`, etc.) don't match because we require the
// literal `=` immediately after `.innerHTML\s*`.
var jsInnerHTMLAssignRe = regexp.MustCompile(`\.innerHTML(\s*)=([^=])`)

// XssPatcher rewrites a single `.innerHTML =` assignment on the matched
// line to `.textContent =`. Declines on zero matches (drift / wrong
// shape) or multiple matches (ambiguous).
func XssPatcher(in PatcherInput) PatcherResult {
	lines := strings.Split(in.Source, "\n")
	idx := in.Match.LineStart - 1
	if idx < 0 || idx >= len(lines) {
		return PatcherResult{Reason: "lineStart out of range — file likely changed since scan"}
	}

	original := lines[idx]
	replacements := 0
	patched := jsInnerHTMLAssignRe.ReplaceAllStringFunc(original, func(m string) string {
		sub := jsInnerHTMLAssignRe.FindStringSubmatch(m)
		replacements++
		return fmt.Sprintf(".textContent%s=%s", sub[1], sub[2])
	})

	if replacements == 0 {
		return PatcherResult{
			Reason: fmt.Sprintf(
				"line %d no longer contains a .innerHTML assignment — file may have drifted, or this is a read/compound-assign (+=) / .outerHTML / .insertAdjacentHTML shape the v1 patcher doesn't handle",
				in.Match.LineStart,
			),
		}
	}
	if replacements > 1 {
		return PatcherResult{
			Reason: fmt.Sprintf("line %d has multiple .innerHTML assignments — manual fix recommended", in.Match.LineStart),
		}
	}

	out := strings.Join(append(append(append([]string{}, lines[:idx]...), patched), lines[idx+1:]...), "\n")
	desc := strings.Join([]string{
		fmt.Sprintf("Replaced `.innerHTML` with `.textContent` on line %d. The", in.Match.LineStart),
		"right-hand value is now rendered as literal text instead of parsed as HTML,",
		"which closes the XSS sink (CWE-79).",
		"",
		"Behavior note: if the value was *meant* to be HTML (e.g. server-rendered",
		"formatted text), this patch will display the markup verbatim — strictly safer,",
		"but possibly not what you want visually. The right fix for that case is to",
		"sanitize the HTML before writing it: `DOMPurify.sanitize(value)` or",
		"`sanitize-html`. Don't undo the patch to bring innerHTML back without a",
		"sanitizer in front of it.",
	}, "\n")

	return PatcherResult{OK: true, Patched: out, Description: desc}
}
