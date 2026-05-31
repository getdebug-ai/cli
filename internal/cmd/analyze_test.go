package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/scan"
)

func TestCountAtOrAbove_FailOnHigh(t *testing.T) {
	fs := []scan.Finding{
		{Severity: scan.SeverityCritical},
		{Severity: scan.SeverityHigh},
		{Severity: scan.SeverityMedium},
		{Severity: scan.SeverityLow},
		{Severity: scan.SeverityInfo},
	}
	// --fail-on=high → critical + high = 2.
	if got := countAtOrAbove(fs, "high"); got != 2 {
		t.Errorf("countAtOrAbove(_, high) = %d, want 2", got)
	}
	// --fail-on=critical → only critical = 1.
	if got := countAtOrAbove(fs, "critical"); got != 1 {
		t.Errorf("countAtOrAbove(_, critical) = %d, want 1", got)
	}
	// --fail-on=medium → critical + high + medium = 3.
	if got := countAtOrAbove(fs, "medium"); got != 3 {
		t.Errorf("countAtOrAbove(_, medium) = %d, want 3", got)
	}
	// --fail-on=low → 4 (everything except info).
	if got := countAtOrAbove(fs, "low"); got != 4 {
		t.Errorf("countAtOrAbove(_, low) = %d, want 4", got)
	}
	// --fail-on=any → also 4 (info is the noise floor; "any" means any
	// concrete severity above info).
	if got := countAtOrAbove(fs, "any"); got != 4 {
		t.Errorf("countAtOrAbove(_, any) = %d, want 4", got)
	}
}

func TestCountAtOrAbove_NoFindings(t *testing.T) {
	if got := countAtOrAbove(nil, "critical"); got != 0 {
		t.Errorf("countAtOrAbove(nil, critical) = %d, want 0", got)
	}
}

func TestThresholdRank_UnknownDefaultsToHigh(t *testing.T) {
	// Defense in depth: even if validation is bypassed, the rank function
	// degrades to "high" rather than something silly like 0.
	if got, want := thresholdRank("bogus"), thresholdRank("high"); got != want {
		t.Errorf("thresholdRank(bogus) = %d, want %d (== high)", got, want)
	}
}

// withAnalyzeFlags resets the package-level flag globals around a test and
// restores them after. The cobra layer normally owns these, but the
// end-to-end test calls runAnalyze directly so the contract under test is
// what main.go sees.
func withAnalyzeFlags(t *testing.T, ci bool, failOn string) {
	t.Helper()
	prevCI, prevFailOn, prevQuiet := analyzeCI, analyzeFailOn, analyzeQuiet
	prevSARIF, prevJSON, prevLocalLLM := analyzeSARIF, analyzeJSON, analyzeLocalLLM
	t.Cleanup(func() {
		analyzeCI, analyzeFailOn, analyzeQuiet = prevCI, prevFailOn, prevQuiet
		analyzeSARIF, analyzeJSON, analyzeLocalLLM = prevSARIF, prevJSON, prevLocalLLM
	})
	analyzeCI = ci
	analyzeFailOn = failOn
	analyzeQuiet = true
	analyzeSARIF = ""
	analyzeJSON = false
	analyzeLocalLLM = false
}

// fakeCobraCmd gives runAnalyze a *cobra.Command whose I/O streams point at
// a buffer the test owns — no leaking to test stdout, no reliance on the
// command tree.
func fakeCobraCmd() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	c := &cobra.Command{Use: "analyze"}
	c.SetOut(&stdout)
	c.SetErr(&stderr)
	return c, &stdout, &stderr
}

// TestRunAnalyze_CIFailOnHigh_PlantedSecret is the launch contract:
// `getdebug analyze . --ci --fail-on=high` must exit non-zero when the
// scan surfaces a finding at or above HIGH. We plant a canonical AWS
// access-key shape — the secrets detector tags those CRITICAL — and assert
// runAnalyze returns ErrCIThresholdExceeded, which main.go translates to
// os.Exit(1).
func TestRunAnalyze_CIFailOnHigh_PlantedSecret(t *testing.T) {
	dir := t.TempDir()
	// AWS docs example access key; matches `\b(AKIA|...)[0-9A-Z]{16}\b` in
	// the secrets regex set. Severity is hard-coded to CRITICAL, so
	// --fail-on=high (which trips on critical+high) must fail.
	planted := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.tf"), []byte(planted), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	withAnalyzeFlags(t, true, "high")
	c, _, stderr := fakeCobraCmd()

	err := runAnalyze(c, []string{dir})
	if !errors.Is(err, ErrCIThresholdExceeded) {
		t.Fatalf("runAnalyze err = %v, want ErrCIThresholdExceeded", err)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("failing build")) {
		t.Errorf("stderr banner missing 'failing build' marker: %q", stderr.String())
	}
}

// TestRunAnalyze_CIFailOnHigh_CleanRepo asserts the inverse: when nothing
// trips the threshold, runAnalyze returns nil and main exits 0.
func TestRunAnalyze_CIFailOnHigh_CleanRepo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.go"), []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	withAnalyzeFlags(t, true, "high")
	c, _, _ := fakeCobraCmd()

	if err := runAnalyze(c, []string{dir}); err != nil {
		t.Fatalf("runAnalyze on clean repo = %v, want nil", err)
	}
}

// TestRunAnalyze_NoCI_FindingsDoNotFail makes sure the contract is gated
// on --ci. A repo full of secrets must NOT fail the build unless --ci is
// explicitly set; the dev should still get the report.
func TestRunAnalyze_NoCI_FindingsDoNotFail(t *testing.T) {
	dir := t.TempDir()
	planted := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.tf"), []byte(planted), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	withAnalyzeFlags(t, false, "high")
	c, _, _ := fakeCobraCmd()

	if err := runAnalyze(c, []string{dir}); err != nil {
		t.Fatalf("runAnalyze without --ci = %v, want nil", err)
	}
}
