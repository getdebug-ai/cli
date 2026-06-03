// Patcher: unbounded-stream (CWE-770).
//
// Port of workers/src/fix/patchers/unbounded-stream.ts. Inserts an
// AbortController declaration above the LLM call and adds
// `signal: controller.signal,` next to the matched `stream: true`
// inside the same options object. Leaves a TODO comment because the
// actual abort() trigger is caller-lifecycle-dependent (Request.signal,
// component unmount, custom hook, etc.) — we can't safely guess.
//
// Heuristics that v1 deliberately keeps simple:
//   - AbortController declaration goes on the line BEFORE the LLM call
//     site. Picking the right scope needs AST work — for the common
//     case (stream: true inside a one-shot async call) statement-above
//     is correct.
//   - signal: controller.signal sits at the SAME indent as `stream: true`,
//     which matches the "one option per line" object-literal style.
//
// Edge cases this v1 will get wrong (acceptable trade-off — git apply +
// downstream validation will catch them):
//   - stream: true on the same line as { and other options
//   - stream: true inside a destructured / spread expression
//   - Existing controller variable already named "controller" — would
//     shadow / collide. Easy follow-up: generate a unique name.

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	streamTrueRe   = regexp.MustCompile(`\bstream\s*:\s*true\b`)
	llmCallShapeRe = regexp.MustCompile(`\.(?:create|invoke|complete|generate|completions)\s*\(`)
	// "(...{...?...$" — line ends with `(` or `({` (possibly trailing
	// whitespace), the shape a multi-line options call starts with.
	openCallSiteRe = regexp.MustCompile(`\(\s*\{?\s*$`)
	decoderDecodeRe = regexp.MustCompile(`\.decode\s*\(`)
)

// UnboundedStreamPatcher adds an AbortController to a streaming LLM
// call. Refuses to patch a `decoder.decode({ stream: true })` line —
// that's the Web Streams API and a known false-positive shape on the
// detector side.
func UnboundedStreamPatcher(in PatcherInput) PatcherResult {
	lines := strings.Split(in.Source, "\n")
	idx := in.Match.LineStart - 1
	if idx < 0 || idx >= len(lines) {
		return PatcherResult{Reason: "lineStart out of range — file likely changed since scan"}
	}

	streamLine := lines[idx]
	if !streamTrueRe.MatchString(streamLine) {
		return PatcherResult{
			Reason: fmt.Sprintf("line %d no longer contains `stream: true` — file likely drifted", in.Match.LineStart),
		}
	}
	if decoderDecodeRe.MatchString(streamLine) {
		return PatcherResult{
			Reason: fmt.Sprintf(
				"line %d is a `decoder.decode({ stream: true })` call — Web Streams API, not an LLM streaming flag. Likely a stale detector false positive; suppress the finding.",
				in.Match.LineStart,
			),
		}
	}

	streamIndent := leadingWsRe.FindString(streamLine)

	// Walk up to find the LLM-call invocation that owns this options
	// object. Same heuristic as TS: ten lines, first .create/.invoke/
	// .complete/.generate/.completions wins; otherwise the first line
	// ending with `(` or `({`.
	callLineIdx := idx
	llmShapeMatched := false
	floor := idx - 10
	if floor < 0 {
		floor = 0
	}
	for i := idx - 1; i >= floor; i-- {
		l := lines[i]
		if llmCallShapeRe.MatchString(l) {
			callLineIdx = i
			llmShapeMatched = true
			break
		}
		if openCallSiteRe.MatchString(l) {
			callLineIdx = i
			// Keep scanning in case a .create() appears further up — but
			// don't reset callLineIdx if we find one; the call-shape match
			// is what would re-anchor us. (Matches the TS behaviour.)
		}
	}

	if !llmShapeMatched && !openCallSiteRe.MatchString(lines[callLineIdx]) {
		return PatcherResult{
			Reason: fmt.Sprintf(
				"line %d's surrounding code doesn't look like an LLM SDK call (no .create / .invoke / .complete / .generate / .completions within 10 lines above). Probably a detector false positive — suppress the finding instead of forcing a patch.",
				in.Match.LineStart,
			),
		}
	}

	callIndent := leadingWsRe.FindString(lines[callLineIdx])
	declLines := []string{
		fmt.Sprintf("%s// getdebug: added AbortController so a stuck stream releases the worker slot.", callIndent),
		fmt.Sprintf("%s// TODO: wire controller.abort() to the caller's lifecycle —", callIndent),
		fmt.Sprintf("%s//   server: req.signal.addEventListener(\"abort\", () => controller.abort())", callIndent),
		fmt.Sprintf("%s//   client: cleanup in useEffect / on component unmount", callIndent),
		fmt.Sprintf("%sconst controller = new AbortController();", callIndent),
	}
	signalLine := fmt.Sprintf("%ssignal: controller.signal,", streamIndent)

	out := make([]string, 0, len(lines)+len(declLines)+1)
	out = append(out, lines[:callLineIdx]...)
	out = append(out, declLines...)
	out = append(out, lines[callLineIdx:idx+1]...) // call line through stream:true line
	out = append(out, signalLine)
	out = append(out, lines[idx+1:]...)

	return PatcherResult{
		OK:          true,
		Patched:     strings.Join(out, "\n"),
		Description: "Inserted an AbortController declaration above the LLM call and added `signal: controller.signal,` to the call options. Left a TODO comment — you still need to wire controller.abort() to whichever lifecycle owns this request (server: req.signal abort, client: useEffect cleanup).",
	}
}
