package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/config"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show your identity, plan, and recent activity",
	Long: `Single-shot snapshot of who you're logged in as, what plan the org is on,
the 5 most recent runs (across all projects), and the 5 most recent fix PRs.

Run after ` + "`getdebug login`" + ` to confirm the token works, or any time
you want a quick read on what getdebug has been doing for you.

Exit codes:
  0  status fetched
  1  not logged in (` + "`getdebug login`" + ` first)
  2  api error`,
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "emit JSON instead of the table")
}

type statusResp struct {
	User struct {
		Email string `json:"email"`
	} `json:"user"`
	Org struct {
		Name      string `json:"name"`
		Plan      string `json:"plan"`
		Suspended bool   `json:"suspended"`
	} `json:"org"`
	RecentRuns []struct {
		ID          string  `json:"id"`
		Project     string  `json:"project"`
		Status      string  `json:"status"`
		Trigger     *string `json:"trigger"`
		Branch      *string `json:"branch"`
		Findings    int     `json:"findings"`
		Fixes       int     `json:"fixes"`
		CreatedAt   string  `json:"createdAt"`
		CompletedAt *string `json:"completedAt"`
	} `json:"recentRuns"`
	RecentPRs []struct {
		Project      string  `json:"project"`
		ProviderPRID string  `json:"providerPrId"`
		Provider     string  `json:"provider"`
		Status       string  `json:"status"`
		Branch       string  `json:"branch"`
		Title        string  `json:"title"`
		URL          string  `json:"url"`
		CreatedAt    string  `json:"createdAt"`
		MergedAt     *string `json:"mergedAt"`
	} `json:"recentPRs"`
}

func runStatus(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Token == "" || cfg.APIBaseURL == "" {
		cmd.PrintErrln("Not logged in. Run `getdebug login` first.")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.APIBaseURL+"/v1/cli/status", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var env struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data,omitempty"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("decode envelope: %w (body=%s)", err, string(body))
	}
	if !env.OK {
		if env.Error != nil && env.Error.Code == "unauthorized" {
			cmd.PrintErrln("Your token was rejected. Run `getdebug login` to re-authenticate.")
			os.Exit(1)
		}
		if env.Error != nil {
			return fmt.Errorf("api: %s: %s", env.Error.Code, env.Error.Message)
		}
		return errors.New("api: unknown error")
	}

	if statusJSON {
		// Pass the data block through unchanged so machine consumers get
		// the same shape the api returned.
		fmt.Fprintln(cmd.OutOrStdout(), string(env.Data))
		return nil
	}

	var s statusResp
	if err := json.Unmarshal(env.Data, &s); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}
	renderStatus(cmd.OutOrStdout(), &s)
	return nil
}

func renderStatus(w io.Writer, s *statusResp) {
	suspended := ""
	if s.Org.Suspended {
		suspended = "  (suspended)"
	}
	fmt.Fprintf(w, "Logged in as %s\n", s.User.Email)
	fmt.Fprintf(w, "Org: %s · plan: %s%s\n\n", s.Org.Name, s.Org.Plan, suspended)

	if len(s.RecentRuns) == 0 {
		fmt.Fprintln(w, "Recent runs: (none yet — connect a repo at the web dashboard to get started)")
	} else {
		fmt.Fprintln(w, "Recent runs:")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  WHEN\tPROJECT\tSTATUS\tBRANCH\tFINDINGS\tFIXES")
		for _, r := range s.RecentRuns {
			branch := "-"
			if r.Branch != nil && *r.Branch != "" {
				branch = *r.Branch
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d\t%d\n",
				humanAgo(r.CreatedAt),
				truncate(r.Project, 28),
				r.Status,
				truncate(branch, 16),
				r.Findings,
				r.Fixes,
			)
		}
		tw.Flush()
	}
	fmt.Fprintln(w)

	if len(s.RecentPRs) == 0 {
		fmt.Fprintln(w, "Recent fix PRs: (none)")
	} else {
		fmt.Fprintln(w, "Recent fix PRs:")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  WHEN\tPROJECT\tPR\tSTATUS\tTITLE")
		for _, p := range s.RecentPRs {
			fmt.Fprintf(tw, "  %s\t%s\t#%s\t%s\t%s\n",
				humanAgo(p.CreatedAt),
				truncate(p.Project, 24),
				p.ProviderPRID,
				p.Status,
				truncate(p.Title, 48),
			)
		}
		tw.Flush()
	}
}

func humanAgo(iso string) string {
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		return iso
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return t.Format("2006-01-02")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

