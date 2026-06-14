package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getdebug-ai/cli/internal/scan"
)

// FIX 6: the TTY renderer was silently dropping f.Verification — every
// secret finding ran the verifier, paid the round-trip, then printed
// like there was no verification information at all. These tests lock
// in the new per-row badge + bottom-of-output summary line.

func TestWriteTable_RendersVerifyBadges(t *testing.T) {
	fs := []scan.Finding{
		{
			Severity: scan.SeverityCritical, Category: "secrets",
			Title: "OpenAI API key detected",
			FilePath: "src/bad.ts", LineStart: 10,
			Verification: &scan.Verification{Status: scan.VerificationValid, Provider: "openai"},
		},
		{
			Severity: scan.SeverityCritical, Category: "secrets",
			Title: "Stripe key detected",
			FilePath: "src/bad.ts", LineStart: 14,
			Verification: &scan.Verification{Status: scan.VerificationInvalid, Provider: "stripe"},
		},
		{
			Severity: scan.SeverityCritical, Category: "secrets",
			Title: "GitHub PAT detected",
			FilePath: "src/bad.ts", LineStart: 18,
			Verification: &scan.Verification{Status: scan.VerificationUnknown, Provider: "github"},
		},
		// One non-secret finding to confirm the row format degrades
		// gracefully when there's no Verification record.
		{
			Severity: scan.SeverityHigh, Category: "sql-injection",
			Title: "String-concat SQL", FilePath: "src/q.ts", LineStart: 4,
		},
	}
	var buf bytes.Buffer
	WriteTable(&buf, fs)
	out := buf.String()

	for _, want := range []string{"[LIVE]", "[REJECTED]", "[UNVERIFIED]"} {
		if !strings.Contains(out, want) {
			t.Errorf("WriteTable output missing %q badge:\n%s", want, out)
		}
	}
	// Bottom-of-output verification summary.
	if !strings.Contains(out, "Verification:") {
		t.Errorf("WriteTable missing Verification: summary line:\n%s", out)
	}
	if !strings.Contains(out, "1 LIVE") || !strings.Contains(out, "1 REJECTED") || !strings.Contains(out, "1 UNVERIFIED") {
		t.Errorf("Verification summary should count 1/1/1, got:\n%s", out)
	}
	// The non-verify row must still print — no Verification record means
	// the badge column is omitted, not "[?]" or similar placeholder.
	if !strings.Contains(out, "String-concat SQL") {
		t.Errorf("non-verify row dropped from output:\n%s", out)
	}
}

// VerifySummary stays empty when no finding carries verification data —
// keeps `analyze .` without --verify uncluttered.
func TestVerifySummary_EmptyWhenNoVerificationData(t *testing.T) {
	fs := []scan.Finding{
		{Severity: scan.SeverityHigh, Category: "sql-injection", Title: "x", FilePath: "a.ts", LineStart: 1},
		{Severity: scan.SeverityMedium, Category: "dependency-cve", Title: "y", FilePath: "go.mod", LineStart: 1},
	}
	if got := VerifySummary(fs, false); got != "" {
		t.Errorf("VerifySummary on no-verify findings = %q, want empty", got)
	}
	var buf bytes.Buffer
	WriteTable(&buf, fs)
	if strings.Contains(buf.String(), "Verification:") {
		t.Errorf("WriteTable should not print Verification: line when no findings have verification:\n%s", buf.String())
	}
}

// Cover the row format change: when a finding HAS a verification record
// the badge appears between severity and location; when it doesn't, the
// row is the legacy "severity loc title" shape so unrelated tooling
// (golden-file diffs, parsers) that grew up around the old format
// stays readable.
func TestWriteTable_RowFormatVariesByVerification(t *testing.T) {
	withVerify := scan.Finding{
		Severity: scan.SeverityCritical, Category: "secrets", Title: "live key",
		FilePath: "a.ts", LineStart: 1,
		Verification: &scan.Verification{Status: scan.VerificationValid},
	}
	without := scan.Finding{
		Severity: scan.SeverityHigh, Category: "sql-injection", Title: "bad query",
		FilePath: "b.ts", LineStart: 2,
	}
	var buf bytes.Buffer
	WriteTable(&buf, []scan.Finding{withVerify, without})
	lines := strings.Split(buf.String(), "\n")

	// Pluck the two header rows (the ones with the file path).
	var verifyRow, plainRow string
	for _, ln := range lines {
		if strings.Contains(ln, "a.ts:1") {
			verifyRow = ln
		}
		if strings.Contains(ln, "b.ts:2") {
			plainRow = ln
		}
	}
	if !strings.Contains(verifyRow, "[LIVE]") {
		t.Errorf("verify row missing badge: %q", verifyRow)
	}
	if strings.Contains(plainRow, "[LIVE]") || strings.Contains(plainRow, "[REJECTED]") || strings.Contains(plainRow, "[UNVERIFIED]") {
		t.Errorf("plain row should not contain a verify badge: %q", plainRow)
	}
}
