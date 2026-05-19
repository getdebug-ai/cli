package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/report"
	"github.com/getdebug-ai/cli/internal/scan"
)

var (
	analyzeWatch  bool
	analyzeCI     bool
	analyzeFailOn string
	analyzeSARIF  string
	analyzeJSON   bool
	analyzeQuiet  bool
)

// validFailOnLevels mirrors the docs: critical | high | medium | low | any.
// "any" means anything above `info` — fail on every concrete finding.
var validFailOnLevels = map[string]struct{}{
	"critical": {},
	"high":     {},
	"medium":   {},
	"low":      {},
	"any":      {},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [path]",
	Short: "Scan a directory for security findings",
	Long: `Walks the given path (default: current directory) and runs getdebug's
local detectors. v1 ships the secrets detector — regex + entropy — which
catches the highest-severity launch blockers (AWS / GitHub / Stripe / OpenAI
keys, private key blocks, high-entropy strings near credential keywords).

Cross-file SAST and the LLM-app pattern catalog require uploading to the
getdebug API, which is on the roadmap and not yet wired into this CLI.

Exit codes:
  0  no findings, or findings below the --fail-on threshold
  1  findings at or above --fail-on threshold (only when --ci is set)
  2  fatal scan error

Examples:
  # Local scan, pretty output:
  getdebug analyze .

  # CI gate — fail the build on any critical finding:
  getdebug analyze . --ci --fail-on=critical

  # Emit SARIF for GitHub Code Scanning:
  getdebug analyze . --sarif=getdebug-results.sarif`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&analyzeWatch, "watch", false, "re-analyze on file changes (Phase 2 — not yet implemented)")
	analyzeCmd.Flags().BoolVar(&analyzeCI, "ci", false, "exit non-zero on findings at or above --fail-on threshold")
	analyzeCmd.Flags().StringVar(&analyzeFailOn, "fail-on", "high", "minimum severity that fails the build under --ci: critical|high|medium|low|any")
	analyzeCmd.Flags().StringVar(&analyzeSARIF, "sarif", "", "write SARIF 2.1.0 results to this path (for GitHub Code Scanning)")
	analyzeCmd.Flags().BoolVar(&analyzeJSON, "json", false, "emit findings as newline-delimited JSON instead of the table")
	analyzeCmd.Flags().BoolVar(&analyzeQuiet, "quiet", false, "suppress the scan-progress banner")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	if analyzeWatch {
		return errors.New("--watch is not yet implemented (Phase 2)")
	}
	if _, ok := validFailOnLevels[analyzeFailOn]; !ok {
		return fmt.Errorf("--fail-on=%q is not one of: critical, high, medium, low, any", analyzeFailOn)
	}

	path := "."
	if len(args) == 1 {
		path = args[0]
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("stat %q: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", abs)
	}

	if !analyzeQuiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "getdebug %s — scanning %s\n", version, abs)
	}
	start := time.Now()
	res, err := scan.ScanSecrets(scan.ScanOptions{Workdir: abs})
	if err != nil {
		// Truly fatal — partial walks never bubble here (the walker swallows
		// per-file errors), so reaching this branch means we couldn't open
		// the root or hit a real disk failure.
		return fmt.Errorf("scan: %w", err)
	}
	elapsed := time.Since(start)

	if !analyzeQuiet {
		hint := ""
		if res.Truncated {
			hint = " (hit 20 MB total-bytes cap; rerun on a smaller subset for full coverage)"
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "scanned %d files in %s%s\n",
			res.ScannedFiles, elapsed.Round(time.Millisecond), hint)
	}

	if analyzeSARIF != "" {
		if err := writeSARIFFile(analyzeSARIF, res.Findings); err != nil {
			return fmt.Errorf("write SARIF: %w", err)
		}
		if !analyzeQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote SARIF → %s\n", analyzeSARIF)
		}
	}

	if analyzeJSON {
		if err := writeNDJSON(cmd.OutOrStdout(), res.Findings); err != nil {
			return fmt.Errorf("write JSON: %w", err)
		}
	} else {
		report.WriteTable(cmd.OutOrStdout(), res.Findings)
	}

	if analyzeCI && countAtOrAbove(res.Findings, analyzeFailOn) > 0 {
		// Print a final banner to stderr so it's visible in CI logs even
		// when stdout is captured to a file.
		fmt.Fprintf(cmd.ErrOrStderr(),
			"\ngetdebug: %d finding(s) at or above --fail-on=%s — failing build.\n",
			countAtOrAbove(res.Findings, analyzeFailOn), analyzeFailOn)
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		os.Exit(1)
	}
	return nil
}

// countAtOrAbove counts findings at or above the threshold for `--fail-on`.
// Lower severityRank = more severe, so we want findings whose rank <= the
// threshold's rank.
func countAtOrAbove(fs []scan.Finding, level string) int {
	limit := thresholdRank(level)
	n := 0
	for _, f := range fs {
		if report.SeverityRank(f.Severity) <= limit {
			n++
		}
	}
	return n
}

func thresholdRank(level string) int {
	switch level {
	case "critical":
		return report.SeverityRank(scan.SeverityCritical)
	case "high":
		return report.SeverityRank(scan.SeverityHigh)
	case "medium":
		return report.SeverityRank(scan.SeverityMedium)
	case "low":
		return report.SeverityRank(scan.SeverityLow)
	case "any":
		// Everything above `info` — Low is the lowest severity that a real
		// detector emits today.
		return report.SeverityRank(scan.SeverityLow)
	default:
		return report.SeverityRank(scan.SeverityHigh)
	}
}
