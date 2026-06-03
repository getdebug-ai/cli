// Patcher: weak-crypto (CWE-327 / CWE-328).
//
// Port of workers/src/fix/patchers/weak-crypto.ts. MD5 and SHA-1 are
// broken for security uses; both have a drop-in replacement in SHA-256
// across Node's crypto and Python's hashlib. This patcher rewrites the
// algorithm string on the matched line and leaves everything else alone.
//
// JS/TS:
//   crypto.createHash("md5"|"sha1")    → crypto.createHash("sha256")
//   crypto.createHmac("md5"|"sha1", …) → crypto.createHmac("sha256", …)
//
// Python:
//   hashlib.md5(…)                       → hashlib.sha256(…)
//   hashlib.sha1(…)                      → hashlib.sha256(…)
//   hashlib.new("md5"|"sha1")            → hashlib.new("sha256")
//
// Edge cases the v1 deliberately skips (decline with reason; finding
// still surfaces as explanation-only):
//   - Multiple weak-hash uses on one line
//   - Algorithm passed as a variable, not a string literal
//   - Languages other than JS/TS/Python
//
// Digest-length follow-up: SHA-256 returns 32 bytes (vs MD5's 16, SHA-1's
// 20). The description warns the dev to verify any downstream code that
// hard-codes the old length.

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// JS/TS — createHash("md5"|"sha1") or createHmac("md5"|"sha1", …).
	// Capture groups: 1=function name, 2=quote char, 3=algorithm.
	jsHashRe = regexp.MustCompile(`\b(createHash|createHmac)\s*\(\s*(['"])\s*(md5|sha1)\s*['"]`)
	// Python — hashlib.md5(…) or hashlib.sha1(…). Capture: 1=algorithm.
	pyHashlibFuncRe = regexp.MustCompile(`\bhashlib\.(md5|sha1)\s*\(`)
	// Python — hashlib.new("md5"|"sha1"). Capture: 1=quote, 2=algorithm.
	pyHashlibNewRe = regexp.MustCompile(`\bhashlib\.new\s*\(\s*(['"])(md5|sha1)['"]`)
)

// WeakCryptoPatcher rewrites a single MD5/SHA-1 hash call on the
// matched line. Returns ok=true when exactly one rewrite was made;
// declines on zero (file drift) or multiple (ambiguous).
func WeakCryptoPatcher(in PatcherInput) PatcherResult {
	lines := strings.Split(in.Source, "\n")
	idx := in.Match.LineStart - 1
	if idx < 0 || idx >= len(lines) {
		return PatcherResult{Reason: "lineStart out of range — file likely changed since scan"}
	}

	original := lines[idx]
	patched := original
	algosFound := map[string]struct{}{}
	replacements := 0

	// JS: createHash / createHmac with quoted md5/sha1.
	patched = jsHashRe.ReplaceAllStringFunc(patched, func(m string) string {
		sub := jsHashRe.FindStringSubmatch(m)
		// sub: [full, fn, quote, algo]
		algosFound[sub[3]] = struct{}{}
		replacements++
		return fmt.Sprintf("%s(%ssha256%s", sub[1], sub[2], sub[2])
	})
	// Python: hashlib.md5(…) / hashlib.sha1(…).
	patched = pyHashlibFuncRe.ReplaceAllStringFunc(patched, func(m string) string {
		sub := pyHashlibFuncRe.FindStringSubmatch(m)
		algosFound[sub[1]] = struct{}{}
		replacements++
		return "hashlib.sha256("
	})
	// Python: hashlib.new("md5") / hashlib.new("sha1").
	patched = pyHashlibNewRe.ReplaceAllStringFunc(patched, func(m string) string {
		sub := pyHashlibNewRe.FindStringSubmatch(m)
		algosFound[sub[2]] = struct{}{}
		replacements++
		return fmt.Sprintf("hashlib.new(%ssha256%s", sub[1], sub[1])
	})

	if replacements == 0 {
		return PatcherResult{
			Reason: fmt.Sprintf("line %d no longer contains a weak-hash call (md5/sha1) — file likely drifted", in.Match.LineStart),
		}
	}
	if replacements > 1 {
		return PatcherResult{
			Reason: fmt.Sprintf("line %d has multiple weak-hash calls — manual fix recommended", in.Match.LineStart),
		}
	}

	out := strings.Join(append(append(append([]string{}, lines[:idx]...), patched), lines[idx+1:]...), "\n")

	algoLabels := make([]string, 0, len(algosFound))
	for a := range algosFound {
		algoLabels = append(algoLabels, strings.ToUpper(a))
	}
	desc := strings.Join([]string{
		fmt.Sprintf("Replaced %s with SHA-256 on line %d. SHA-256 has a drop-in API", strings.Join(algoLabels, "/"), in.Match.LineStart),
		"in both Node's `crypto` and Python's `hashlib`, so no other call-site changes are needed.",
		"",
		"Verify downstream: SHA-256 digests are 32 bytes (MD5 = 16, SHA-1 = 20). If anything",
		"hard-codes the old length — database columns, fixed-width displays, truncations — widen",
		"it before merging.",
	}, "\n")

	return PatcherResult{
		OK:          true,
		Patched:     out,
		Description: desc,
	}
}
