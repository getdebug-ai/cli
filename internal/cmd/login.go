package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/api"
	"github.com/getdebug-ai/cli/internal/config"
)

var (
	loginAPIBaseURL string
	loginNoBrowser  bool
	loginClientName string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate against the getdebug API",
	Long: `Walks the OAuth 2.0 device flow (RFC 8628):

  1. We request a one-time code from the api.
  2. You open the printed URL in your browser and click Approve.
  3. We poll the api until you approve (or the code expires after 10 min).
  4. The returned token is written to ~/.getdebug/config.json — every
     subsequent ` + "`getdebug`" + ` command authenticates with it.

The plaintext token is shown to you once during the flow and never re-displayed.
Revoke it any time from ` + "`/settings/cli`" + ` on the web dashboard.`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginAPIBaseURL, "api", defaultAPIBaseURL(), "getdebug API base URL")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "skip auto-opening the browser; print the URL only")
	loginCmd.Flags().StringVar(&loginClientName, "name", defaultClientName(), "label shown on the approval page + in the dashboard's CLI tokens list")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if loginAPIBaseURL == "" {
		return errors.New("--api is required (or set GETDEBUG_API_URL)")
	}
	client, err := api.New(loginAPIBaseURL, "")
	if err != nil {
		return fmt.Errorf("--api: %w", err)
	}

	cmd.PrintErrf("Requesting device code from %s …\n", loginAPIBaseURL)
	code, err := client.RequestDeviceCode(ctx, loginClientName)
	if err != nil {
		return fmt.Errorf("request device code: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  First, copy your one-time code:")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "      %s\n", code.UserCode)
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  Then open this URL to approve:")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "      %s\n", code.VerificationURLComplete)
	fmt.Fprintln(cmd.OutOrStdout())

	if !loginNoBrowser {
		if err := openBrowser(code.VerificationURLComplete); err != nil {
			// Non-fatal — the URL is already printed. Just note we couldn't
			// open it automatically.
			cmd.PrintErrf("(couldn't open browser: %v — open the URL above manually)\n", err)
		}
	}

	cmd.PrintErrln("Waiting for approval — Ctrl+C to cancel.")
	pollInterval := time.Duration(code.Interval) * time.Second
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	pollCtx, pollCancel := context.WithTimeout(ctx, time.Duration(code.ExpiresIn)*time.Second)
	defer pollCancel()

	dots := 0
	token, err := client.PollUntilApproved(pollCtx, code.DeviceCode, pollInterval, 30*time.Second, func() {
		dots++
		// Cap progress dots to avoid endless scroll on a long wait.
		if dots <= 60 {
			cmd.PrintErr(".")
		}
	})
	cmd.PrintErrln()
	if err != nil {
		switch {
		case errors.Is(err, api.ErrAccessDenied):
			return errors.New("login denied in the browser")
		case errors.Is(err, api.ErrExpiredToken), errors.Is(err, context.DeadlineExceeded):
			return errors.New("login code expired — re-run `getdebug login` to try again")
		case errors.Is(err, context.Canceled):
			return errors.New("login canceled")
		default:
			return fmt.Errorf("poll: %w", err)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.APIBaseURL = loginAPIBaseURL
	cfg.Token = token.Token
	cfg.UserEmail = token.UserEmail
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	path, _ := config.Path()
	cmd.PrintErrf("\nLogged in as %s.\nToken saved to %s (mode 0600).\n",
		token.UserEmail, path)
	return nil
}

// defaultAPIBaseURL prefers the env var, then the config file (if a previous
// login already pinned one), then the production default. Letting the env
// var override means CI / dev can point at staging without flags.
func defaultAPIBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("GETDEBUG_API_URL")); v != "" {
		return v
	}
	cfg, _ := config.Load()
	if cfg != nil && cfg.APIBaseURL != "" {
		return cfg.APIBaseURL
	}
	return "https://api.getdebug.dev"
}

// defaultClientName is what shows up on the approval page + in the dashboard's
// CLI tokens list — picking the hostname so users can tell "the Mac on my
// desk" from "my Linux box" at a glance.
func defaultClientName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "getdebug CLI"
}

// openBrowser is best-effort. On Linux we try `xdg-open` first; on macOS,
// `open`; on Windows, `cmd /c start`. Failure is non-fatal — the URL is
// already printed.
func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	return exec.Command(cmd, args...).Start()
}
