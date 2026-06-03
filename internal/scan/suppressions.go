// CLI-side suppression context — the local mirror of
// workers/src/security/suppression-context.ts.
//
// Phase 1.7 Item 4. When the user has a `.getdebug/suppressions.json` file
// in the workdir, sastlocal.go reads it and splices a "TEAM-ACCEPTED
// PATTERNS" block into the local model's system prompt — same shape as the
// hosted side. The model then stops generating findings the team already
// rejected, instead of producing them and having them filtered at
// write-time.
//
// File format (an array of records):
//
//   [
//     {
//       "category": "command-injection",
//       "patternId": null,
//       "scope": "project",
//       "reason": "All exec() calls flow through sandbox.runSandboxed which validates input."
//     }
//   ]
//
// The file is FIRST-PARTY (written by a team member, committed to the
// repo), so it lives outside the TRUST BOUNDARY block in the prompt — the
// model is told to treat it as policy. The model still sees the actual file
// content as untrusted.
//
// Honest degradation: a missing file is fine (silent), an unreadable or
// malformed file is logged and the scan continues with no suppression
// context. We never fail a scan over a bad suppressions file.

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// suppressionsRelPath is the canonical location inside a project.
const suppressionsRelPath = ".getdebug/suppressions.json"

// suppressionContextItem mirrors the workers TS shape exactly. Drift here
// means the hosted and local "learning" loops disagree on what the team
// has accepted.
type suppressionContextItem struct {
	Category  string  `json:"category"`
	PatternID *string `json:"patternId"`
	Scope     string  `json:"scope"` // "org" or "project"
	Reason    string  `json:"reason"`
}

// suppressionContext is the per-scan rendered view.
type suppressionContext struct {
	items []suppressionContextItem
}

const (
	maxSuppressionPromptItems = 20
	maxSuppressionReasonChars = 240
)

// loadSuppressionContext reads `.getdebug/suppressions.json` from the
// workdir, normalises and caps the contents, and returns a context ready
// for rendering. A missing file returns an empty context with nil err — the
// expected case for any project that hasn't opted into the loop yet.
//
// Logf is the same logger sastlocal passes around, so any honest-status
// notes (malformed file, dropped items) show up next to the rest of the
// scan output.
func loadSuppressionContext(workdir string, logf func(string, ...any)) suppressionContext {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	path := filepath.Join(workdir, suppressionsRelPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("sast-local: %s present but unreadable (%v) — continuing without learning context", suppressionsRelPath, err)
		}
		return suppressionContext{}
	}

	var parsed []suppressionContextItem
	if err := json.Unmarshal(raw, &parsed); err != nil {
		logf("sast-local: %s malformed JSON (%v) — continuing without learning context", suppressionsRelPath, err)
		return suppressionContext{}
	}

	// Normalise + drop items the model can't use:
	//   - missing category or reason → no actionable signal
	//   - scope other than org/project → guard against typos that would
	//     otherwise render an ambiguous "[]" label in the prompt
	//   - trim reason to the cap so one verbose entry can't blow the budget
	out := make([]suppressionContextItem, 0, len(parsed))
	for _, it := range parsed {
		it.Category = strings.TrimSpace(it.Category)
		it.Reason = strings.TrimSpace(it.Reason)
		if it.Category == "" || it.Reason == "" {
			continue
		}
		if it.Scope != "org" && it.Scope != "project" {
			it.Scope = "project"
		}
		if len(it.Reason) > maxSuppressionReasonChars {
			it.Reason = it.Reason[:maxSuppressionReasonChars]
		}
		if it.PatternID != nil {
			p := strings.TrimSpace(*it.PatternID)
			if p == "" {
				it.PatternID = nil
			} else {
				it.PatternID = &p
			}
		}
		out = append(out, it)
	}

	// Dedupe by (category, patternId, reason). Two suppressions with the
	// same reason on the same pattern carry the same model signal.
	seen := make(map[string]struct{}, len(out))
	deduped := out[:0]
	for _, it := range out {
		patternKey := ""
		if it.PatternID != nil {
			patternKey = *it.PatternID
		}
		key := it.Category + "|" + patternKey + "|" + it.Reason
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, it)
	}

	// Stable order so the prompt (and any cache derived from it) doesn't
	// jitter across runs of the same suppressions file.
	sort.SliceStable(deduped, func(i, j int) bool {
		if deduped[i].Category != deduped[j].Category {
			return deduped[i].Category < deduped[j].Category
		}
		pi, pj := "", ""
		if deduped[i].PatternID != nil {
			pi = *deduped[i].PatternID
		}
		if deduped[j].PatternID != nil {
			pj = *deduped[j].PatternID
		}
		if pi != pj {
			return pi < pj
		}
		return deduped[i].Reason < deduped[j].Reason
	})

	if len(deduped) > maxSuppressionPromptItems {
		deduped = deduped[:maxSuppressionPromptItems]
	}

	return suppressionContext{items: deduped}
}

// renderSuppressionBlock returns the system-prompt section. Empty string
// when the context has no items — callers can safely concatenate.
//
// The framing matches the hosted side: first-party team policy, outside
// the TRUST BOUNDARY markers. The model is told to recognise NEW variants
// rather than blindly suppress the category.
func (c suppressionContext) renderSuppressionBlock() string {
	if len(c.items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("TEAM-ACCEPTED PATTERNS (first-party policy — trusted, not part of the file):\n")
	b.WriteString("The team has previously reviewed and explicitly accepted these patterns in this codebase.\n")
	b.WriteString("Treat them as known-safe in their accepted form. Do NOT re-flag them.\n")
	b.WriteString("DO flag NEW variants that look similar but behave differently, and explain the relationship.\n")
	b.WriteString("\n")
	for _, it := range c.items {
		target := it.Category + " (category-wide)"
		if it.PatternID != nil {
			target = fmt.Sprintf("%s / pattern=%s", it.Category, *it.PatternID)
		}
		fmt.Fprintf(&b, "  - [%s] %s — %s\n", it.Scope, target, it.Reason)
	}
	b.WriteString("\n")
	return b.String()
}
