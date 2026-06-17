package localllm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ChatJSON must surface Ollama's prompt_eval_count / eval_count as Usage so the
// CLI can print its per-scan token + hosted-equivalent-cost banner.
func TestChatJSON_CapturesTokenUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"m","message":{"role":"assistant","content":"{\"findings\":[]}"},"done":true,"prompt_eval_count":123,"eval_count":45}`))
	}))
	defer srv.Close()

	text, usage, err := New(srv.URL).ChatJSON(context.Background(), "m", []Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("ChatJSON: %v", err)
	}
	if text != `{"findings":[]}` {
		t.Fatalf("content = %q, want the unwrapped JSON", text)
	}
	if usage.PromptTokens != 123 || usage.OutputTokens != 45 {
		t.Fatalf("usage = %+v, want {PromptTokens:123 OutputTokens:45}", usage)
	}
}

// Token counts are still captured when the model wraps its JSON in ```json
// fences (the fence-stripping path), and missing counts degrade to zero.
func TestChatJSON_FencedContentAndMissingCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"message\":{\"content\":\"```json\\n{\\\"findings\\\":[]}\\n```\"}}"))
	}))
	defer srv.Close()

	text, usage, err := New(srv.URL).ChatJSON(context.Background(), "m", nil)
	if err != nil {
		t.Fatalf("ChatJSON: %v", err)
	}
	if text != `{"findings":[]}` {
		t.Fatalf("content = %q, want fences stripped", text)
	}
	if usage.PromptTokens != 0 || usage.OutputTokens != 0 {
		t.Fatalf("usage = %+v, want zero when counts absent", usage)
	}
}
