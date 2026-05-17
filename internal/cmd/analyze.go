package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	analyzeWatch bool
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [path]",
	Short: "Analyze a directory for bugs and surface findings",
	Long: `Walks the given path (default: current directory), uploads file
chunks to the getdebug API, kicks off an analysis run, and streams findings
back to the terminal. Findings also appear in the web dashboard if you're
signed in.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		path := "."
		if len(args) == 1 {
			path = args[0]
		}
		fmt.Printf("getdebug analyze %s: not yet implemented (Phase 1)\n", path)
		return nil
	},
}

func init() {
	analyzeCmd.Flags().BoolVar(&analyzeWatch, "watch", false, "re-analyze on file changes (Phase 2)")
}
