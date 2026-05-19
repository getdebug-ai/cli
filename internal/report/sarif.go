// Package report formats scan results for humans (terminal table) and
// machines (SARIF). Output formats live here rather than in scan/ so the
// detector package stays focused on detection.
package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/getdebug-ai/cli/internal/scan"
)

// SARIF v2.1.0 minimal subset. Spec:
//   https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
// We emit only what GitHub Code Scanning ingests today — additional fields
// are optional and add noise without value.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	FullDescription  sarifMessage           `json:"fullDescription,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
	DefaultConfig    *sarifConfig           `json:"defaultConfiguration,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints lets GitHub correlate the same finding across
	// commits even when surrounding lines change.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// severityToLevel maps our internal severity onto the SARIF level enum.
// SARIF only knows {none, note, warning, error} — we collapse our 5-tier
// scale onto those.
func severityToLevel(sev string) string {
	switch sev {
	case scan.SeverityCritical, scan.SeverityHigh:
		return "error"
	case scan.SeverityMedium:
		return "warning"
	case scan.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// WriteSARIF serializes findings as a SARIF 2.1.0 log to w. The rules
// section is the set of unique (category, pattern) pairs seen in the
// findings — Code Scanning groups results by rule, so emitting a stable
// rule per pattern gives a cleaner dashboard.
func WriteSARIF(w io.Writer, findings []scan.Finding, toolVersion string) error {
	rulesByID := map[string]sarifRule{}
	for _, f := range findings {
		id := ruleID(f)
		if _, exists := rulesByID[id]; exists {
			continue
		}
		rulesByID[id] = sarifRule{
			ID:               id,
			Name:             ruleName(f),
			ShortDescription: sarifMessage{Text: ruleName(f)},
			FullDescription:  sarifMessage{Text: f.Explanation},
			Properties: map[string]interface{}{
				"category": f.Category,
				"cwe":      f.CWE,
				"owasp":    f.OWASP,
				"tags":     []string{"security", f.Category},
			},
			DefaultConfig: &sarifConfig{Level: severityToLevel(f.Severity)},
		}
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, r := range rulesByID {
		rules = append(rules, r)
	}
	// Stable rule order so a no-change run yields byte-identical SARIF —
	// useful for diffing CI artifacts.
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		end := f.LineEnd
		if end <= f.LineStart {
			end = 0 // omit when same line — SARIF treats absent endLine as = startLine.
		}
		results = append(results, sarifResult{
			RuleID:  ruleID(f),
			Level:   severityToLevel(f.Severity),
			Message: sarifMessage{Text: f.Title},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.FilePath},
					Region:           sarifRegion{StartLine: f.LineStart, EndLine: end},
				},
			}},
			PartialFingerprints: map[string]string{
				"getdebug/contentHash": f.ContentHash,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "getdebug",
				Version:        toolVersion,
				InformationURI: "https://github.com/getdebug-ai/cli",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func ruleID(f scan.Finding) string {
	// Stable, kebab-case rule IDs. GitHub uses these as the link target on
	// the Code Scanning rule page, so they want to be readable.
	switch {
	case f.Category == "secrets" && f.Detection == "regex" && f.Pattern != "":
		return "secrets/" + slug(f.Pattern)
	case f.Category == "secrets" && f.Detection == "entropy":
		return "secrets/high-entropy-near-keyword"
	default:
		return f.Category
	}
}

func ruleName(f scan.Finding) string {
	if f.Pattern != "" {
		return f.Pattern
	}
	return f.Title
}

// slug lowercases and hyphenates an identifier. ASCII-only; the inputs are
// our own pattern labels so we don't need a unicode-aware slugifier.
func slug(s string) string {
	out := make([]byte, 0, len(s))
	prevHyphen := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
			prevHyphen = false
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			out = append(out, c)
			prevHyphen = false
		default:
			if !prevHyphen && len(out) > 0 {
				out = append(out, '-')
				prevHyphen = true
			}
		}
	}
	// Trim trailing hyphen.
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}
