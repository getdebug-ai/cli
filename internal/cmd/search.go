package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/config"
)

var (
	searchProjectID string
	searchK         int
	searchLangs     []string
	searchJSON      bool
	searchTrigger   bool
)

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Semantic search across your indexed codebase",
	Long: `Embeds your query and runs an ANN search against the project's code index.
Returns the top-K most-similar chunks (functions, methods, classes).

Free-tier feature — the indexer (workers/src/code-index.ts) and search
endpoint don't gate on plan. Cross-file SAST and the git-history
narrative that USE the index for Pro Plus depth are separate features.

The index has to exist first — kick one off with --trigger (or via the
web dashboard's "Index now" button).`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSearch,
}

func init() {
	searchCmd.Flags().StringVar(&searchProjectID, "project", "", "project id (required)")
	searchCmd.Flags().IntVar(&searchK, "k", 10, "number of results")
	searchCmd.Flags().StringSliceVar(&searchLangs, "lang", nil, "filter by language (repeatable)")
	searchCmd.Flags().BoolVar(&searchJSON, "json", false, "emit JSON instead of the formatted list")
	searchCmd.Flags().BoolVar(&searchTrigger, "trigger", false, "instead of searching, enqueue a full re-index of the project")
	_ = searchCmd.MarkFlagRequired("project")
}

type searchResult struct {
	ChunkID   string  `json:"chunkId"`
	RelPath   string  `json:"relPath"`
	Language  string  `json:"language"`
	Kind      string  `json:"kind"`
	LineStart int     `json:"lineStart"`
	LineEnd   int     `json:"lineEnd"`
	Score     float64 `json:"score"`
	Content   string  `json:"content"`
}

type searchResponse struct {
	Query   string         `json:"query"`
	K       int            `json:"k"`
	Results []searchResult `json:"results"`
}

func runSearch(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Token == "" || cfg.APIBaseURL == "" {
		cmd.PrintErrln("Not logged in. Run `getdebug login` first.")
		os.Exit(1)
	}

	if searchTrigger {
		return triggerIndex(cmd, cfg, searchProjectID)
	}

	query := strings.TrimSpace(strings.Join(args, " "))
	if query == "" {
		return errors.New("query required")
	}

	body := map[string]any{
		"query": query,
		"k":     searchK,
	}
	if len(searchLangs) > 0 {
		body["languages"] = searchLangs
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	var resp searchResponse
	if err := apiPost(ctx, cfg, "/v1/projects/"+searchProjectID+"/search", body, &resp); err != nil {
		return err
	}

	if searchJSON {
		out, _ := json.Marshal(resp)
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	if len(resp.Results) == 0 {
		cmd.Println("No matches. Has this project been indexed? Re-run with --trigger to kick one off.")
		return nil
	}

	for i, r := range resp.Results {
		fmt.Fprintf(cmd.OutOrStdout(), "\n%d. \033[36m%s:%d-%d\033[0m  (%s · %s · score=%.3f)\n",
			i+1, r.RelPath, r.LineStart, r.LineEnd, r.Kind, r.Language, r.Score)
		fmt.Fprintln(cmd.OutOrStdout(), indent(r.Content, "   "))
	}
	return nil
}

func triggerIndex(cmd *cobra.Command, cfg *config.Config, projectID string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()
	var resp struct {
		JobID  string `json:"jobId"`
		Status string `json:"status"`
	}
	if err := apiPost(ctx, cfg, "/v1/projects/"+projectID+"/index", map[string]any{}, &resp); err != nil {
		return err
	}
	cmd.Printf("Queued code-index job %s (status=%s). Re-run `getdebug search` once the workers complete it.\n",
		resp.JobID, resp.Status)
	return nil
}

// ─── HTTP helper (POST) ─────────────────────────────────────────

func apiPost(ctx context.Context, cfg *config.Config, path string, body any, out any) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIBaseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()
	respBody, err := io.ReadAll(res.Body)
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
	if err := json.Unmarshal(respBody, &env); err != nil {
		return fmt.Errorf("decode envelope: %w (body=%s)", err, string(respBody))
	}
	if !env.OK {
		if env.Error != nil && env.Error.Code == "unauthorized" {
			fmt.Fprintln(os.Stderr, "Your token was rejected. Run `getdebug login`.")
			os.Exit(1)
		}
		if env.Error != nil {
			return fmt.Errorf("api: %s: %s", env.Error.Code, env.Error.Message)
		}
		return errors.New("api: unknown error")
	}
	if out != nil {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("decode data: %w", err)
		}
	}
	return nil
}

// indent prefixes every line of s with prefix.
func indent(s, prefix string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
