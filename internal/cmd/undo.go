package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var undoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Restore files modified by the most recent --apply",
	Long: `Reads the most recent .getdebug-backup-<timestamp>/ directory and
restores its contents over the working tree. If multiple backup directories
exist, the most recent is used unless --timestamp is given.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Println("getdebug undo: not yet implemented (Phase 1)")
		return nil
	},
}
