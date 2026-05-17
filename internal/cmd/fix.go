package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	fixApply       bool
	fixInteractive bool
	fixLocalOnly   bool
	fixCI          bool
)

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Generate and (optionally) apply fixes for findings",
	Long: `Default is --dry-run: shows the diff but writes nothing. Pass --apply
to write the patch to disk — getdebug first creates a .getdebug-backup-<timestamp>/
directory next to each modified file so 'getdebug undo' can restore them.

Patches that fail validation (parse, typecheck, or tests if getdebug.yml opts in)
are reported but never applied.

Security-sensitive categories (auth, crypto, secrets, sql-injection) are
explanation-only unless you set allowSecurityFixes: true in getdebug.yml.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		path := "."
		if len(args) == 1 {
			path = args[0]
		}
		mode := "dry-run"
		if fixApply {
			mode = "apply"
		}
		if fixInteractive {
			mode = "interactive"
		}
		fmt.Printf("getdebug fix %s [mode=%s, local-only=%v, ci=%v]: not yet implemented (Phase 1)\n",
			path, mode, fixLocalOnly, fixCI)
		return nil
	},
}

func init() {
	fixCmd.Flags().BoolVar(&fixApply, "apply", false, "write fixes to disk (default: dry-run)")
	fixCmd.Flags().BoolVar(&fixInteractive, "interactive", false, "walk through each fix")
	fixCmd.Flags().BoolVar(&fixLocalOnly, "local-only", false, "call Claude directly from this machine using your own API key (no upload)")
	fixCmd.Flags().BoolVar(&fixCI, "ci", false, "exit non-zero on any unfixed finding above threshold severity (Phase 2)")
}
