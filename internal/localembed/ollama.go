// Local embeddings via Ollama (https://ollama.ai).
//
// Why Ollama: lots of devs already run it (LLM hobby use), it ships small
// embedding models like nomic-embed-text out of the box, and "install
// Ollama, pull a model" is a familiar setup. No CGO, no bundled binaries
// on our side — the CLI stays a pure-Go single binary.
//
// API shape (https://github.com/ollama/ollama/blob/main/docs/api.md):
//
//   POST /api/embed
//     { "model": "nomic-embed-text", "input": "text" | ["text", …] }
//     → { "model": "...", "embeddings": [[…floats…], …] }
//
// We use the newer /api/embed (batched) over the legacy /api/embeddings
// (single-input) because indexing a real repo means thousands of inputs.

package localembed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is where Ollama listens by default. Users running it on
// a non-default host/port set GETDEBUG_OLLAMA_URL.
const DefaultBaseURL = "http://localhost:11434"

// DefaultModel — small, fast, decent recall on prose + code. ~270MB on
// disk. The user installs it once: `ollama pull nomic-embed-text`.
const DefaultModel = "nomic-embed-text"

// DefaultDim matches nomic-embed-text v1.5.
const DefaultDim = 768

// Client is the minimal HTTP client we need. Stateless aside from the
// configured base URL + http.Client; safe to reuse.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a client with sane defaults. 5-minute per-request timeout
// because nomic-embed-text on CPU can chew through a batch of 16 large
// chunks in 60-120s. The outer context (set by the command) is the real
// wall-clock budget; this is the per-HTTP-call guard.
func New(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 5 * time.Minute},
	}
}

// Ping checks the Ollama server is reachable + the requested model is
// available. Returns a human-readable error pointing the user at how to
// fix it — the failure mode IS the v0.2 onboarding flow for new users.
func (c *Client) Ping(ctx context.Context, model string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf(
			"can't reach Ollama at %s — is it running? Install: https://ollama.ai. (%w)",
			c.BaseURL, err,
		)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama responded %d at /api/tags", res.StatusCode)
	}
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tags); err != nil {
		return fmt.Errorf("decode /api/tags: %w", err)
	}
	// Ollama tags include a `:latest` suffix; allow either form.
	want := strings.TrimSuffix(model, ":latest")
	for _, m := range tags.Models {
		if m.Name == model || strings.TrimSuffix(m.Name, ":latest") == want {
			return nil
		}
	}
	return fmt.Errorf(
		"ollama doesn't have %q yet — run: ollama pull %s",
		model, model,
	)
}

// MaxInputBytes caps each input before sending. nomic-embed-text accepts
// up to 8192 tokens; ~4 chars/token = 32KB. We stay at 24KB for a 25%
// safety margin — embedding a truncated chunk still gives a useful vector
// (filename + first ~600 lines is plenty for retrieval) and a clear cap
// is better than guessing the model's exact tokeniser behaviour.
const MaxInputBytes = 24 * 1024

// EmbedBatch sends up to N texts in one /api/embed call. Ollama returns
// vectors in the same order; we return them as []float32 so downstream
// math + storage (vector(N) BLOB) doesn't pay a float64 tax. Inputs are
// truncated at MaxInputBytes — over-long content is a real possibility
// in generated / minified files and we'd rather index a prefix than
// drop the chunk.
func (c *Client) EmbedBatch(ctx context.Context, model string, inputs []string) ([][]float32, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	capped := make([]string, len(inputs))
	for i, s := range inputs {
		if len(s) > MaxInputBytes {
			capped[i] = s[:MaxInputBytes]
		} else {
			capped[i] = s
		}
	}
	body, err := json.Marshal(map[string]any{
		"model": model,
		"input": capped,
	})
	if err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/embed", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Model      string      `json:"model"`
		Embeddings [][]float32 `json:"embeddings"`
		Error      string      `json:"error,omitempty"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w (body=%s)", err, string(raw))
	}
	if out.Error != "" {
		return nil, errors.New(out.Error)
	}
	if len(out.Embeddings) != len(inputs) {
		return nil, fmt.Errorf("ollama returned %d vectors for %d inputs", len(out.Embeddings), len(inputs))
	}
	return out.Embeddings, nil
}

// EmbedOne is a convenience wrapper for single-input queries (the search
// path). Re-uses EmbedBatch under the hood — Ollama treats single + batch
// the same way.
func (c *Client) EmbedOne(ctx context.Context, model, input string) ([]float32, error) {
	vecs, err := c.EmbedBatch(ctx, model, []string{input})
	if err != nil {
		return nil, err
	}
	if len(vecs) == 0 {
		return nil, errors.New("ollama returned no embeddings")
	}
	return vecs[0], nil
}
