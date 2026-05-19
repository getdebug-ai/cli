package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getdebug-ai/cli/internal/scan"
)

func TestWriteSARIF_EmitsValidStructure(t *testing.T) {
	findings := []scan.Finding{
		{
			FilePath: "src/config.ts", LineStart: 14, LineEnd: 14,
			Category: "secrets", Severity: scan.SeverityCritical,
			Title: "AWS access key detected", Explanation: "rotate now",
			ContentHash: "deadbeef0001", Detection: "regex",
			Pattern: "AWS access key", CWE: "CWE-798", OWASP: "A07:2021",
		},
		{
			FilePath: "src/util.ts", LineStart: 7, LineEnd: 7,
			Category: "secrets", Severity: scan.SeverityCritical,
			Title: "AWS access key detected", Explanation: "rotate now",
			ContentHash: "deadbeef0002", Detection: "regex",
			Pattern: "AWS access key", CWE: "CWE-798", OWASP: "A07:2021",
		},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("emitted SARIF is not valid JSON: %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if !strings.Contains(log.Schema, "sarif-2.1.0") {
		t.Errorf("schema URI does not reference 2.1.0: %q", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "getdebug" {
		t.Errorf("driver name = %q, want getdebug", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.1.0" {
		t.Errorf("driver version = %q, want 0.1.0", run.Tool.Driver.Version)
	}

	// Both findings share a pattern → one rule, two results.
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 (deduped by pattern); got: %+v", len(run.Tool.Driver.Rules), run.Tool.Driver.Rules)
	}
	if len(run.Tool.Driver.Rules) > 0 && run.Tool.Driver.Rules[0].DefaultConfiguration.Level != "error" {
		t.Errorf("critical → SARIF level = %q, want error", run.Tool.Driver.Rules[0].DefaultConfiguration.Level)
	}

	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	for i, r := range run.Results {
		if r.Level != "error" {
			t.Errorf("result %d level = %q, want error", i, r.Level)
		}
		if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %d missing location: %+v", i, r.Locations)
		}
		// PartialFingerprints carries the contentHash for cross-commit
		// correlation by GitHub Code Scanning.
		if got := r.PartialFingerprints["getdebug/contentHash"]; got != findings[i].ContentHash {
			t.Errorf("result %d fingerprint = %q, want %q", i, got, findings[i].ContentHash)
		}
	}
}

func TestSeverityToLevel_Mapping(t *testing.T) {
	cases := []struct {
		sev, want string
	}{
		{scan.SeverityCritical, "error"},
		{scan.SeverityHigh, "error"},
		{scan.SeverityMedium, "warning"},
		{scan.SeverityLow, "note"},
		{scan.SeverityInfo, "none"},
	}
	for _, c := range cases {
		if got := severityToLevel(c.sev); got != c.want {
			t.Errorf("severityToLevel(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestRuleID_Stable(t *testing.T) {
	f := scan.Finding{Category: "secrets", Detection: "regex", Pattern: "AWS access key"}
	if got, want := ruleID(f), "secrets/aws-access-key"; got != want {
		t.Errorf("ruleID = %q, want %q", got, want)
	}
	f2 := scan.Finding{Category: "secrets", Detection: "entropy"}
	if got, want := ruleID(f2), "secrets/high-entropy-near-keyword"; got != want {
		t.Errorf("entropy ruleID = %q, want %q", got, want)
	}
}
