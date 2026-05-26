package cmd

import "github.com/spf13/cobra"

// version is wired at build time via -ldflags '-X .../internal/cmd.version=...'
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "getdebug",
	Short: "AI-powered codebase analyzer and auto-fixer",
	Long: `getdebug finds bugs in your codebase, generates patches that fix them,
validates the patches, and either opens a PR (hosted repos) or stages the
fix for local apply via the CLI.

Default behavior of ` + "`getdebug fix`" + ` is dry-run — you must pass --apply
to write to disk. Every --apply writes a .getdebug-backup-<timestamp>/
directory next to the files it modifies so ` + "`getdebug undo`" + ` can restore them.`,
	Version: version,
}

// Execute is the entrypoint called from cmd/getdebug/main.go.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(indexCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(fixCmd)
	rootCmd.AddCommand(undoCmd)
}
