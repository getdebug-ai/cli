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

func TestWriteSARIF_MultiCWEPropagatesToTagsAndArrays(t *testing.T) {
	// unsafe-tool-output is the canonical multi-CWE category: CWE-94 is the
	// broader code-injection parent (eval/Function/vm.runIn*) and CWE-78 is
	// the OS command-injection subset (subprocess.run/spawn). The SARIF
	// emitter has to surface BOTH so GitHub Code Scanning indexes the
	// finding under both CWE pages.
	findings := []scan.Finding{
		{
			FilePath: "app.py", LineStart: 4, LineEnd: 4,
			Category: "unsafe-tool-output", Severity: scan.SeverityCritical,
			Title: "subprocess.run with model tool output", Explanation: "...",
			ContentHash: "feedface0001",
			CWE: "CWE-94", OWASP: "A08:2021",
			SecondaryCWE: "CWE-78", SecondaryOWASP: "A03:2021",
		},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						Properties map[string]interface{} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule, got runs=%d rules=%d", len(log.Runs), len(log.Runs[0].Tool.Driver.Rules))
	}
	props := log.Runs[0].Tool.Driver.Rules[0].Properties

	// `cwe` / `owasp` stay as the primary strings for back-compat.
	if got, want := props["cwe"], "CWE-94"; got != want {
		t.Errorf("cwe = %v, want %v", got, want)
	}
	if got, want := props["owasp"], "A08:2021"; got != want {
		t.Errorf("owasp = %v, want %v", got, want)
	}
	// `cwes` / `owasps` arrays carry the full set when multi-valued.
	cwes, _ := props["cwes"].([]interface{})
	if len(cwes) != 2 || cwes[0] != "CWE-94" || cwes[1] != "CWE-78" {
		t.Errorf("cwes = %v, want [CWE-94 CWE-78]", cwes)
	}
	owasps, _ := props["owasps"].([]interface{})
	if len(owasps) != 2 || owasps[0] != "A08:2021" || owasps[1] != "A03:2021" {
		t.Errorf("owasps = %v, want [A08:2021 A03:2021]", owasps)
	}
	// GitHub Code Scanning consumes `external/cwe/cwe-<n>` tags. Both
	// CWEs MUST appear in the tags so the finding shows up under both
	// CWE pages on the Security tab.
	tags, _ := props["tags"].([]interface{})
	var have94, have78 bool
	for _, t := range tags {
		switch t {
		case "external/cwe/cwe-94":
			have94 = true
		case "external/cwe/cwe-78":
			have78 = true
		}
	}
	if !have94 || !have78 {
		t.Errorf("expected both external/cwe/cwe-94 AND external/cwe/cwe-78 tags; got %v", tags)
	}
}

func TestWriteSARIF_SingleCWE_OmitsArrayForms(t *testing.T) {
	// Categories with a single CWE (the common case) should NOT emit the
	// `cwes` / `owasps` array forms — `cwe` / `owasp` strings are enough,
	// and adding redundant single-element arrays would just bloat the file.
	findings := []scan.Finding{{
		FilePath: "src/x.ts", LineStart: 1, LineEnd: 1,
		Category: "sql-injection", Severity: scan.SeverityHigh,
		Title: "SQLi", Explanation: "...",
		ContentHash: "feedface0002",
		CWE: "CWE-89", OWASP: "A03:2021",
	}}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if strings.Contains(buf.String(), `"cwes"`) {
		t.Errorf("single-CWE finding should not emit `cwes` array; got: %s", buf.String())
	}
	if strings.Contains(buf.String(), `"owasps"`) {
		t.Errorf("single-OWASP finding should not emit `owasps` array; got: %s", buf.String())
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
