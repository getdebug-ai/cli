package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/getdebug-ai/cli/internal/scan"
)

// Severity ordering for sort + ranking against `--fail-on`.
var severityRank = map[string]int{
	scan.SeverityCritical: 0,
	scan.SeverityHigh:     1,
	scan.SeverityMedium:   2,
	scan.SeverityLow:      3,
	scan.SeverityInfo:     4,
}

// SeverityRank returns the ordinal for cmp purposes. Lower = more severe.
// Returns a high number for unknown severities so they sort last.
func SeverityRank(sev string) int {
	if r, ok := severityRank[sev]; ok {
		return r
	}
	return 99
}

// WriteTable prints findings to w grouped by file, severity-sorted within
// each file. ANSI colors are enabled when out is a TTY; piped output stays
// plain so logs and `| less` don't get garbled escape codes.
func WriteTable(w io.Writer, findings []scan.Finding) {
	color := isTTY(w)

	// Defensive copy + stable sort: most-severe first, then file then line.
	fs := make([]scan.Finding, len(findings))
	copy(fs, findings)
	sort.SliceStable(fs, func(i, j int) bool {
		if a, b := SeverityRank(fs[i].Severity), SeverityRank(fs[j].Severity); a != b {
			return a < b
		}
		if fs[i].FilePath != fs[j].FilePath {
			return fs[i].FilePath < fs[j].FilePath
		}
		return fs[i].LineStart < fs[j].LineStart
	})

	if len(fs) == 0 {
		fmt.Fprintln(w, paint(color, "ok", "✓ No security findings."))
		return
	}

	for _, f := range fs {
		badge := severityBadge(color, f.Severity)
		loc := fmt.Sprintf("%s:%d", f.FilePath, f.LineStart)
		fmt.Fprintf(w, "%s  %s  %s\n", badge, paint(color, "loc", loc), f.Title)
		if f.Snippet != "" {
			fmt.Fprintf(w, "       %s %s\n", paint(color, "dim", "↳"), truncate(f.Snippet, 100))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, Summary(fs, color))
}

// Summary returns a one-line counts breakdown — used by both the table
// output and CI mode's failure banner.
func Summary(fs []scan.Finding, color bool) string {
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	parts := []string{}
	for _, sev := range []string{scan.SeverityCritical, scan.SeverityHigh, scan.SeverityMedium, scan.SeverityLow, scan.SeverityInfo} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, paintSeverity(color, sev)))
		}
	}
	if len(parts) == 0 {
		return paint(color, "ok", "0 findings")
	}
	return fmt.Sprintf("%d total — %s", len(fs), strings.Join(parts, ", "))
}

func severityBadge(color bool, sev string) string {
	label := strings.ToUpper(sev)
	if !color {
		return fmt.Sprintf("[%s]", label)
	}
	switch sev {
	case scan.SeverityCritical:
		return "\x1b[1;41;97m " + label + " \x1b[0m" // white on red bg
	case scan.SeverityHigh:
		return "\x1b[1;31m" + label + "\x1b[0m"
	case scan.SeverityMedium:
		return "\x1b[1;33m" + label + "\x1b[0m"
	case scan.SeverityLow:
		return "\x1b[1;36m" + label + "\x1b[0m"
	default:
		return "\x1b[1;90m" + label + "\x1b[0m"
	}
}

func paintSeverity(color bool, sev string) string {
	if !color {
		return sev
	}
	switch sev {
	case scan.SeverityCritical:
		return "\x1b[1;31m" + sev + "\x1b[0m"
	case scan.SeverityHigh:
		return "\x1b[31m" + sev + "\x1b[0m"
	case scan.SeverityMedium:
		return "\x1b[33m" + sev + "\x1b[0m"
	case scan.SeverityLow:
		return "\x1b[36m" + sev + "\x1b[0m"
	default:
		return sev
	}
}

func paint(color bool, kind, s string) string {
	if !color {
		return s
	}
	switch kind {
	case "loc":
		return "\x1b[36m" + s + "\x1b[0m"
	case "dim":
		return "\x1b[2m" + s + "\x1b[0m"
	case "ok":
		return "\x1b[32m" + s + "\x1b[0m"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// isTTY returns true when w is a *os.File pointing at a terminal. Anything
// else (pipes, bytes.Buffer in tests, file redirects) gets plain output.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
