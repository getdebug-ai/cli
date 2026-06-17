// Local chat-completion via Ollama (https://ollama.ai).
//
// Sibling of cli/internal/localembed/ollama.go — that one handles the
// embeddings half of `getdebug index --local` / `search --local`; this one
// handles chat-completion for `getdebug analyze --local-llm`, so the SAST
// pass can run on a local model (DeepSeek/Qwen/Llama) with code never
// leaving the laptop. No API key, no spend, no upload — the true Rule-2
// escape hatch (CLAUDE.md), now for analysis too.
//
// API shape (https://github.com/ollama/ollama/blob/main/docs/api.md):
//
//   POST /api/chat
//     { "model": "qwen2.5-coder:7b",
//       "messages": [{ "role": "system"|"user"|"assistant", "content": "..." }],
//       "stream": false,
//       "format": "json",        -- forces structured-JSON output
//       "options": { "temperature": 0.1 } }
//     → { "model": "...", "message": { "role": "assistant", "content": "..." }, "done": true }
//
// We force `stream:false` + `format:"json"` because the SAST prompt asks
// for a JSON findings array — letting the model wander into prose costs
// us a retry. "format=json" is honoured by most chat-capable Ollama models;
// fallback parsing strips markdown fences just in case.

package localllm

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

// DefaultBaseURL mirrors localembed — Ollama listens on 11434 by default.
// GETDEBUG_OLLAMA_URL overrides for custom hosts.
const DefaultBaseURL = "http://localhost:11434"

// DefaultModel — Qwen2.5-Coder 7B is the best small-model code-aware option
// on Ollama today (Apache-2.0, ~4.7GB Q4, JSON-mode-friendly). Users can
// override with --local-llm-model; popular alternatives: deepseek-r1:7b,
// llama3.1:8b. We pick a code-specialized default so SAST-style prompts
// degrade gracefully on weak models.
const DefaultModel = "qwen2.5-coder:7b"

// Client is the minimal HTTP client we need. Stateless aside from the
// configured base URL + http.Client; safe to reuse across calls.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a client with sane defaults. 10-minute per-request timeout —
// chat completions on CPU for a non-trivial source file can take 2-5 min
// on a 7B model; the outer context is still the wall-clock budget.
func New(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 10 * time.Minute},
	}
}

// Ping mirrors localembed.Ping — server reachable + model installed.
// Returned errors point at the fix (install Ollama / pull the model)
// because this IS the onboarding error message for new users.
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

// Message is one turn in the chat request. Roles match OpenAI's: system /
// user / assistant — Ollama is OpenAI-API-compatible enough that the
// hosted SAST prompt format ports cleanly.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatJSON sends `messages` to Ollama in JSON-output mode and returns the
// assistant's content string. Caller json.Unmarshal's it against the
// expected shape. We do NOT parse here — keeping JSON parsing in the
// caller lets each prompt own its own response schema.
//
// Temperature defaults to 0.1 (consistent classification, not creative).
// Usage reports the token counts Ollama returns for one chat call. The local
// model runs on-device so the dollar cost is zero; these counts let the CLI
// print a per-scan token banner (and a "what this would cost on a hosted model"
// comparison that makes the air-gap's value explicit).
type Usage struct {
	PromptTokens int
	OutputTokens int
}

func (c *Client) ChatJSON(ctx context.Context, model string, messages []Message) (string, Usage, error) {
	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": messages,
		"stream":   false,
		"format":   "json",
		"options":  map[string]any{"temperature": 0.1},
	})
	if err != nil {
		return "", Usage{}, fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", Usage{}, fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return "", Usage{}, fmt.Errorf("read body: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return "", Usage{}, fmt.Errorf("ollama %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	// prompt_eval_count = input tokens, eval_count = generated tokens (Ollama's
	// native field names). Absent on very old Ollama builds → zero, harmless.
	var out struct {
		Model           string  `json:"model"`
		Message         Message `json:"message"`
		Done            bool    `json:"done"`
		Error           string  `json:"error,omitempty"`
		PromptEvalCount int     `json:"prompt_eval_count"`
		EvalCount       int     `json:"eval_count"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", Usage{}, fmt.Errorf("decode response: %w (body=%s)", err, string(raw))
	}
	if out.Error != "" {
		return "", Usage{}, errors.New(out.Error)
	}
	usage := Usage{PromptTokens: out.PromptEvalCount, OutputTokens: out.EvalCount}
	// Some models still wrap content in ```json fences despite format=json.
	// Strip them so the caller's json.Unmarshal succeeds.
	content := strings.TrimSpace(out.Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	return strings.TrimSpace(content), usage, nil
}
