package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the most recent run + applied fixes",
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Println("getdebug status: not yet implemented (Phase 1)")
		return nil
	},
}
