// Patcher: insecure-random (CWE-338).
//
// Port of workers/src/fix/patchers/insecure-random.ts. Math.random() is a
// predictable Mersenne-Twister-style PRNG; the drop-in for "uniform float
// in [0, 1)" from a CSPRNG is:
//
//   Math.random()
//     → (crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296)
//
// `crypto` is a global on every runtime this codebase targets (browsers,
// Node ≥ 19, Deno, Bun, edge runtimes). The replacement is wrapped in
// parens so it composes the same way as the original expression in
// arithmetic contexts (e.g. `Math.random() * n` → `(…) * n`).
//
// Python (random.random() → secrets.SystemRandom().random()) is
// intentionally deferred — the fix crosses a module boundary (needs an
// `import secrets` injected and tracked), which the pure-function
// patcher contract doesn't model. Python findings still surface as
// explanation-only.
//
// Edge cases the v1 deliberately skips (decline with reason; finding
// still surfaces as explanation-only):
//   - Multiple Math.random() calls on one line
//   - Anything other than the literal `Math.random()` shape (e.g. aliased,
//     `const r = Math.random; r()`)
//   - Non-JS/TS files

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	jsMathRandomRe = regexp.MustCompile(`\bMath\.random\s*\(\s*\)`)
)

const mathRandomReplacement = "(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296)"

// InsecureRandomPatcher rewrites a single Math.random() on the matched
// line. Returns ok=true when exactly one rewrite was made; declines on
// zero (drift / alias / non-literal) or multiple (ambiguous).
func InsecureRandomPatcher(in PatcherInput) PatcherResult {
	lines := strings.Split(in.Source, "\n")
	idx := in.Match.LineStart - 1
	if idx < 0 || idx >= len(lines) {
		return PatcherResult{Reason: "lineStart out of range — file likely changed since scan"}
	}

	original := lines[idx]
	replacements := 0
	patched := jsMathRandomRe.ReplaceAllStringFunc(original, func(string) string {
		replacements++
		return mathRandomReplacement
	})

	if replacements == 0 {
		return PatcherResult{
			Reason: fmt.Sprintf(
				"line %d no longer contains a Math.random() call — file likely drifted, or the random source is a non-literal pattern (alias, destructure, dynamic) the v1 patcher doesn't handle",
				in.Match.LineStart,
			),
		}
	}
	if replacements > 1 {
		return PatcherResult{
			Reason: fmt.Sprintf("line %d has multiple Math.random() calls — manual fix recommended", in.Match.LineStart),
		}
	}

	out := strings.Join(append(append(append([]string{}, lines[:idx]...), patched), lines[idx+1:]...), "\n")
	desc := strings.Join([]string{
		fmt.Sprintf("Replaced Math.random() on line %d with a Web Crypto draw", in.Match.LineStart),
		"(`crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296`). Same return shape —",
		"a uniform float in [0, 1) — but sourced from the platform CSPRNG instead of a",
		"predictable PRNG, which closes CWE-338.",
		"",
		"Runtime note: `crypto` is a global in browsers, Node ≥ 19, Deno, Bun, and every edge",
		"runtime. If this file runs on Node ≤ 18, add `import { webcrypto as crypto } from",
		`"node:crypto";` + " at the top — otherwise the patch is drop-in.",
	}, "\n")

	return PatcherResult{
		OK:          true,
		Patched:     out,
		Description: desc,
	}
}
