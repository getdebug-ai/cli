package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate against the getdebug API",
	Long: `Opens a browser, walks the OAuth flow, and writes the returned token
to ~/.getdebug/config.json. Subsequent commands use that token.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		// TODO Phase 1 week 1-2: OAuth device flow — open browser, poll for token,
		// write to ~/.getdebug/config.json.
		fmt.Println("getdebug login: not yet implemented (Phase 1)")
		return nil
	},
}
