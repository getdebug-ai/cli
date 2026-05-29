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
	"github.com/getdebug-ai/cli/internal/localembed"
	"github.com/getdebug-ai/cli/internal/localindex"
)

var (
	searchProjectID   string
	searchK           int
	searchLangs       []string
	searchJSON        bool
	searchLocal       bool
	searchOllamaURL   string
	searchOllamaModel string
)

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Semantic search across your indexed codebase",
	Long: `Embeds your query and runs an ANN search against the project's code index.
Returns the top-K most-similar chunks (functions, methods, classes).

Two modes:

  --local            Search the local index for the current repo. Your code
                     never leaves your laptop. Index first with
                     ` + "`getdebug index --local`" + `.

  --project <id>     Search the server-side index. Index first with
                     ` + "`getdebug index --project <id>`" + ` or via the
                     web dashboard.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSearch,
}

func init() {
	searchCmd.Flags().StringVar(&searchProjectID, "project", "", "project id (remote mode)")
	searchCmd.Flags().BoolVar(&searchLocal, "local", false, "search the local index for the current repo")
	searchCmd.Flags().IntVar(&searchK, "k", 10, "number of results")
	searchCmd.Flags().StringSliceVar(&searchLangs, "lang", nil, "filter by language (repeatable)")
	searchCmd.Flags().BoolVar(&searchJSON, "json", false, "emit JSON instead of the formatted list")
	searchCmd.Flags().StringVar(&searchOllamaURL, "ollama-url", envOr("GETDEBUG_OLLAMA_URL", localembed.DefaultBaseURL), "Ollama base URL (local mode)")
	searchCmd.Flags().StringVar(&searchOllamaModel, "model", envOr("GETDEBUG_OLLAMA_MODEL", localembed.DefaultModel), "Ollama embedding model (local mode)")
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
	query := strings.TrimSpace(strings.Join(args, " "))
	if query == "" {
		return errors.New("query required")
	}

	if searchLocal {
		return runLocalSearch(cmd, query)
	}

	if searchProjectID == "" {
		return errors.New("either --local or --project <id> is required")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Token == "" || cfg.APIBaseURL == "" {
		cmd.PrintErrln("Not logged in. Run `getdebug login` first.")
		os.Exit(1)
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
		cmd.Println("No matches. Has this project been indexed? Run `getdebug index --project <id>` first.")
		return nil
	}

	for i, r := range resp.Results {
		fmt.Fprintf(cmd.OutOrStdout(), "\n%d. \033[36m%s:%d-%d\033[0m  (%s · %s · score=%.3f)\n",
			i+1, r.RelPath, r.LineStart, r.LineEnd, r.Kind, r.Language, r.Score)
		fmt.Fprintln(cmd.OutOrStdout(), indent(r.Content, "   "))
	}
	return nil
}

// runLocalSearch queries the on-disk index built by `getdebug index --local`.
// Never touches the api or network — embedding goes to Ollama on localhost,
// ANN runs in-process.
func runLocalSearch(cmd *cobra.Command, query string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer cancel()

	root, err := gitRepoRootOrCwd()
	if err != nil {
		return err
	}
	originURL := gitRemoteOriginURL()

	ollama := localembed.New(searchOllamaURL)
	if err := ollama.Ping(ctx, searchOllamaModel); err != nil {
		return err
	}
	// Probe dim — must match what was used at index time. The store will
	// refuse to open if the model changed, with a clearer error.
	probe, err := ollama.EmbedOne(ctx, searchOllamaModel, "hello")
	if err != nil {
		return fmt.Errorf("ollama probe: %w", err)
	}
	store, err := localindex.Open(originURL, root, searchOllamaModel, len(probe))
	if err != nil {
		return err
	}
	defer store.Close()

	queryVec, err := ollama.EmbedOne(ctx, searchOllamaModel, query)
	if err != nil {
		return fmt.Errorf("embed query: %w", err)
	}
	results, err := store.Search(queryVec, searchK, searchLangs)
	if err != nil {
		return err
	}

	if searchJSON {
		out, _ := json.Marshal(struct {
			Query   string         `json:"query"`
			K       int            `json:"k"`
			Results []searchResult `json:"results"`
		}{
			Query: query,
			K:     searchK,
			Results: mapResults(results),
		})
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	if len(results) == 0 {
		cmd.Println("No matches in the local index. Run `getdebug index --local` first?")
		return nil
	}
	for i, r := range results {
		fmt.Fprintf(cmd.OutOrStdout(), "\n%d. \033[36m%s:%d-%d\033[0m  (%s · %s · score=%.3f)\n",
			i+1, r.RelPath, r.LineStart, r.LineEnd, r.Kind, r.Language, r.Score)
		fmt.Fprintln(cmd.OutOrStdout(), indent(r.Content, "   "))
	}
	return nil
}

func mapResults(in []localindex.SearchResult) []searchResult {
	out := make([]searchResult, len(in))
	for i, r := range in {
		out[i] = searchResult{
			ChunkID:   r.ChunkID,
			RelPath:   r.RelPath,
			Language:  r.Language,
			Kind:      r.Kind,
			LineStart: r.LineStart,
			LineEnd:   r.LineEnd,
			Score:     r.Score,
			Content:   r.Content,
		}
	}
	return out
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
