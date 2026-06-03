// Local fix engine — Phase 1.7 Item 2.
//
// Mirrors the hosted patcher contract from workers/src/fix/patchers/types.ts:
// a Patcher is a pure function over (file source, match site) → (new
// source + dev explanation) or a structured failure. No I/O, no network,
// no DB. The engine in engine.go orchestrates around it, providing the
// detector (regex scan of the workdir) and the apply path (.getdebug-
// backup-<ts>/ + write).
//
// This is the deterministic half of `getdebug fix --local-only` — the
// patches that don't need an LLM call. Categories that DO need LLM
// reasoning to produce a safe patch (sql-injection, command-injection,
// missing-auth) intentionally have no entry in the registry. Findings
// in those categories surface as explanation-only, same as on the hosted
// side. Bringing the LLM-driven patchers up locally is Item 2-bis.

package fix

// MatchSite is the location a detector emitted — same 1-based line
// numbers and matched-text shape the regex passes already use.
type MatchSite struct {
	LineStart   int
	LineEnd     int
	MatchedSpan string
}

// PatcherInput is everything a patcher needs to do its work. No
// embedded *os.File, no path resolution — the engine reads the file
// once and hands it in.
type PatcherInput struct {
	// Source is the full content of the file under patch.
	Source string
	// FilePath is the workdir-relative path. Used only for messages —
	// the patcher does not perform any filesystem operation with it.
	FilePath string
	// Match is the detector-emitted location to operate on.
	Match MatchSite
	// Context carries detector-specific fields a small subset of
	// patchers need (e.g. dependency-cve reads packageName +
	// fixedVersion). Most patchers ignore it. Mirrors the hosted
	// PatcherInput.context contract.
	Context map[string]string
}

// PatcherResult is the sum type a patcher returns. Either it produced a
// new file content + a dev-readable explanation (OK = true), or it
// declined to patch with a reason the engine surfaces honestly (OK =
// false). A patcher never panics on bad input — drift, oversized files,
// and structurally unfixable shapes are all decline-with-reason cases.
type PatcherResult struct {
	OK bool
	// Patched is the full file content after the patch — only set when OK.
	// The engine computes the diff for display; patchers don't emit unified
	// diffs themselves.
	Patched string
	// Description is the dev-readable summary: what was changed, what
	// follow-up the dev needs to do. Surfaced in the CLI summary after
	// `getdebug fix --local-only --apply`.
	Description string
	// Reason is the explain-why-not when OK is false. Always present in
	// the decline case so the CLI can render an honest skip note.
	Reason string
	// ManualCommand is an optional copy-pastable shell command for the
	// "structurally unfixable but the dev can fix it" case (e.g.
	// dependency-cve hitting a JS lockfile whose integrity hash the
	// patcher can't recompute). When set on a decline (OK=false), the
	// CLI prints it as a suggested follow-up instead of just dropping
	// the finding silently. Mirrors workers PatcherResult.manualCommand.
	ManualCommand string
}

// Patcher is the contract the registry maps category → impl against.
type Patcher func(PatcherInput) PatcherResult

// Registry maps a security category to its deterministic patcher. A
// category absent from this map has no auto-fix locally — surface as
// explanation-only, never invent a patch. New patchers register here.
//
// Mirrors workers/src/fix/patchers/index.ts (`patchers`).
var Registry = map[string]Patcher{
	"client-side-llm-key": ClientSideLlmKeyPatcher,
	"dependency-cve":      DependencyCvePatcher,
	"insecure-cors":       InsecureCorsPatcher,
	"insecure-random":     InsecureRandomPatcher,
	"open-redirect":       OpenRedirectPatcher,
	"unbounded-stream":    UnboundedStreamPatcher,
	"weak-crypto":         WeakCryptoPatcher,
	"xss":                 XssPatcher,
}

// Lookup returns the patcher for a category, or nil if none is
// registered. nil-return is the explicit "no auto-fix locally" signal —
// callers must check it before invoking.
func Lookup(category string) Patcher {
	if p, ok := Registry[category]; ok {
		return p
	}
	return nil
}
