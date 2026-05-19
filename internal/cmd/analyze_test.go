package cmd

import (
	"testing"

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
