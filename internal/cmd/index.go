package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/config"
	"github.com/getdebug-ai/cli/internal/localchunk"
	"github.com/getdebug-ai/cli/internal/localembed"
	"github.com/getdebug-ai/cli/internal/localindex"
)

var (
	indexLocal       bool
	indexProjectID   string
	indexOllamaURL   string
	indexOllamaModel string
	indexBatch       int
)

var indexCmd = &cobra.Command{
	Use:   "index",
	Short: "Build (or update) the code intelligence index",
	Long: `Two modes:

  --local   Index the current repo on this machine. Embeds with Ollama
            (https://ollama.ai), stores at ~/.getdebug/projects/<id>/.
            Your code never leaves your laptop.

  default   Enqueue a server-side index job for the project. Requires
            --project. The api clones the repo on getdebug's workers and
            embeds using the configured EMBEDDINGS_API_KEY.

Once indexed, query with:

  getdebug search --local "your query"             (local mode)
  getdebug search --project <id> "your query"      (remote mode)
`,
	RunE: runIndex,
}

func init() {
	indexCmd.Flags().BoolVar(&indexLocal, "local", false, "index the current repo locally via Ollama (no upload)")
	indexCmd.Flags().StringVar(&indexProjectID, "project", "", "project id (required for remote-side indexing)")
	indexCmd.Flags().StringVar(&indexOllamaURL, "ollama-url", envOr("GETDEBUG_OLLAMA_URL", localembed.DefaultBaseURL), "Ollama base URL (local mode)")
	indexCmd.Flags().StringVar(&indexOllamaModel, "model", envOr("GETDEBUG_OLLAMA_MODEL", localembed.DefaultModel), "Ollama embedding model (local mode)")
	indexCmd.Flags().IntVar(&indexBatch, "batch", 16, "embedding batch size (local mode)")
}

func runIndex(cmd *cobra.Command, _ []string) error {
	if indexLocal {
		return runLocalIndex(cmd)
	}
	if indexProjectID == "" {
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
	return triggerRemoteIndex(cmd, cfg, indexProjectID)
}

func runLocalIndex(cmd *cobra.Command) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()

	root, err := gitRepoRootOrCwd()
	if err != nil {
		return err
	}
	originURL := gitRemoteOriginURL() // may be empty for repos with no origin

	ollama := localembed.New(indexOllamaURL)

	// Friendly pre-flight: fail before doing any work if Ollama isn't
	// reachable / model isn't pulled. The error message IS the
	// onboarding instructions.
	if err := ollama.Ping(ctx, indexOllamaModel); err != nil {
		return err
	}

	// Probe the model's actual dimension by embedding a 1-token sample.
	// Different models return different sizes (nomic-embed-text → 768,
	// mxbai-embed-large → 1024, etc.), and we want to commit the right
	// vector(N) shape to the local sqlite on first run.
	probe, err := ollama.EmbedOne(ctx, indexOllamaModel, "hello")
	if err != nil {
		return fmt.Errorf("ollama probe failed: %w", err)
	}
	dim := len(probe)
	cmd.PrintErrf("Ollama %s · %d-dim embeddings · ready.\n", indexOllamaModel, dim)

	store, err := localindex.Open(originURL, root, indexOllamaModel, dim)
	if err != nil {
		return err
	}
	defer store.Close()

	cmd.PrintErrf("Walking %s …\n", root)
	chunks, fileCount, err := localchunk.ChunkRepo(root, func(p string, e error) {
		// Don't spam — quiet on per-file errors during the walk.
		_ = p
		_ = e
	})
	if err != nil {
		return fmt.Errorf("walk: %w", err)
	}
	cmd.PrintErrf("Scanned %d file(s) → %d chunks.\n", fileCount, len(chunks))

	// Dedup: skip chunks whose content_hash is already in the local store
	// (re-running `getdebug index --local` on an unchanged file is free).
	toEmbed := make([]localindex.Chunk, 0, len(chunks))
	for _, c := range chunks {
		has, err := store.HasChunk(c.ContentHash)
		if err != nil {
			return fmt.Errorf("hash lookup: %w", err)
		}
		if !has {
			toEmbed = append(toEmbed, c)
		}
	}
	cmd.PrintErrf("New chunks to embed: %d (skipping %d unchanged).\n", len(toEmbed), len(chunks)-len(toEmbed))

	if len(toEmbed) == 0 {
		// Still bump the manifest so `getdebug status` reflects today's run.
		_ = store.UpdateLastIndexed(commitShaOrEmpty(root))
		cmd.Printf("Index is up to date at %s\n", store.Dir())
		return nil
	}

	embedded := 0
	skipped := 0
	for i := 0; i < len(toEmbed); i += indexBatch {
		end := i + indexBatch
		if end > len(toEmbed) {
			end = len(toEmbed)
		}
		batch := toEmbed[i:end]
		texts := make([]string, len(batch))
		for j, c := range batch {
			texts[j] = c.ContentText
		}
		vecs, err := ollama.EmbedBatch(ctx, indexOllamaModel, texts)
		if err != nil {
			// Try each input one at a time so a single bad chunk doesn't
			// drop the rest of the batch. Common cause: a file the
			// truncation cap can't save (e.g. a 16KB chunk that's all
			// tokens — Ollama's `400 input length exceeds context length`).
			cmd.PrintErrf("  batch failed (%v) — retrying individually\n", err)
			for j, c := range batch {
				vec, singleErr := ollama.EmbedOne(ctx, indexOllamaModel, texts[j])
				if singleErr != nil {
					cmd.PrintErrf("    skip %s:%d-%d (%v)\n", c.RelPath, c.LineStart, c.LineEnd, singleErr)
					skipped++
					continue
				}
				id := randomID()
				if err := store.Upsert(id, c, vec); err != nil {
					return fmt.Errorf("upsert: %w", err)
				}
				embedded++
			}
			cmd.PrintErrf("  embedded %d / %d (skipped %d)\n", embedded, len(toEmbed), skipped)
			continue
		}
		for j, c := range batch {
			id := randomID()
			if err := store.Upsert(id, c, vecs[j]); err != nil {
				return fmt.Errorf("upsert: %w", err)
			}
		}
		embedded += len(batch)
		cmd.PrintErrf("  embedded %d / %d\n", embedded, len(toEmbed))
	}
	if skipped > 0 {
		cmd.PrintErrf("Skipped %d chunk(s) the embedding model rejected.\n", skipped)
	}

	if err := store.UpdateLastIndexed(commitShaOrEmpty(root)); err != nil {
		return fmt.Errorf("manifest update: %w", err)
	}

	total, _ := store.CountChunks()
	cmd.Printf("\nLocal index ready: %d chunks at %s\n", total, store.Dir())
	cmd.Println("Query with:  getdebug search --local \"your query\"")
	return nil
}

func triggerRemoteIndex(cmd *cobra.Command, cfg *config.Config, projectID string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()
	var resp struct {
		JobID  string `json:"jobId"`
		Status string `json:"status"`
	}
	if err := apiPost(ctx, cfg, "/v1/projects/"+projectID+"/index", map[string]any{}, &resp); err != nil {
		return err
	}
	cmd.Printf("Queued remote code-index job %s (status=%s).\n", resp.JobID, resp.Status)
	cmd.Println("Once the workers finish, query with:")
	cmd.Printf("  getdebug search --project %s \"your query\"\n", projectID)
	return nil
}

// ─── small helpers shared with fix.go ───────────────────────────

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// gitRepoRootOrCwd prefers the git root (so chunks have stable rel paths)
// and falls back to cwd for non-git directories — local mode shouldn't
// require git when a dev is just exploring a downloaded codebase.
func gitRepoRootOrCwd() (string, error) {
	if root, err := gitRepoRoot(); err == nil {
		return root, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cwd: %w", err)
	}
	return cwd, nil
}

// gitRemoteOriginURL is the full URL (or "" if there isn't one). The
// localindex package wants this to derive a stable project key.
func gitRemoteOriginURL() string {
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func commitShaOrEmpty(_ string) string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a timestamp string — never hit in practice.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

