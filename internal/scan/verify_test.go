package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubServer routes every request to a per-test handler that returns a
// status code (and optionally inspects the URL / headers via the test).
func stubServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// secret returns a synthetic Finding shaped like one the regex pass would
// emit (pattern label drives the verifier choice; snippet is the candidate
// credential).
func secret(pattern, snippet string) Finding {
	return Finding{
		FilePath:    "src/leak.go",
		LineStart:   1,
		LineEnd:     1,
		Category:    "secrets",
		Severity:    "critical",
		Title:       pattern + " detected",
		Explanation: "x",
		ContentHash: pattern + "::" + snippet,
		Pattern:     pattern,
		Detection:   "regex",
		Snippet:     snippet,
	}
}

// rewriteClient routes every outgoing request through the stub server,
// keeping the original Host header so per-provider handlers can branch on
// it. This is how we substitute api.openai.com (etc.) in tests without
// touching the real internet.
func rewriteClient(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	tsURL := ts.URL
	return &http.Client{
		Transport: roundTripFn(func(req *http.Request) (*http.Response, error) {
			// Preserve the original host as a header so the handler can switch on it.
			req.Header.Set("X-Test-Original-Host", req.URL.Host)
			req.URL.Scheme = "http"
			req.URL.Host = strings.TrimPrefix(tsURL, "http://")
			req.Host = req.URL.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}
}

type roundTripFn func(*http.Request) (*http.Response, error)

func (f roundTripFn) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestVerifyFindings_OpenAI_200Valid(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Original-Host") != "api.openai.com" {
			t.Errorf("unexpected host: %s", r.Header.Get("X-Test-Original-Host"))
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth, got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(200)
	})
	defer ts.Close()
	in := []Finding{secret("OpenAI API key", "sk-proj-validkey0123456789abcdef0123456789")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationValid {
		t.Errorf("expected valid, got %+v", got)
	}
}

func TestVerifyFindings_Anthropic_xAPIKeyHeader_401Invalid(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "" {
			t.Error("anthropic verifier must send x-api-key header")
		}
		w.WriteHeader(401)
	})
	defer ts.Close()
	in := []Finding{secret("Anthropic API key", "sk-ant-api03-rejectedkey0123456789abcdef0123456789")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationInvalid {
		t.Errorf("expected invalid, got %+v", got)
	}
}

func TestVerifyFindings_GitHub_200_and_401(t *testing.T) {
	// Findings are verified concurrently, so we can't assume call order
	// (first finding hits handler first). Instead, route on the key the
	// handler sees in the Authorization header: a key containing "good"
	// returns 200, anything else 401.
	const goodKey = "ghp_goodgoodgoodgoodgoodgoodgoodgoodgood"
	const badKey = "github_pat_11badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad"
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("github verifier hit %s, expected /user", r.URL.Path)
		}
		if strings.Contains(r.Header.Get("Authorization"), goodKey) {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	})
	defer ts.Close()
	in := []Finding{
		secret("GitHub PAT (classic)", goodKey),
		secret("GitHub fine-grained PAT", badKey),
	}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if out[0].Verification == nil || out[0].Verification.Status != VerificationValid {
		t.Errorf("expected good key valid, got %+v", out[0].Verification)
	}
	if out[1].Verification == nil || out[1].Verification.Status != VerificationInvalid {
		t.Errorf("expected bad key invalid, got %+v", out[1].Verification)
	}
}

func TestVerifyFindings_Stripe_BasicAuth(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("stripe verifier must use Basic auth, got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(200)
	})
	defer ts.Close()
	// synthetic key, split across literals so GitHub push-protection doesn't flag this fixture
	in := []Finding{secret("Stripe secret key", "sk_live_"+"abcabcabcabcabcabcabcabcabc")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationValid {
		t.Errorf("expected valid, got %+v", got)
	}
}

func TestVerifyFindings_5xxMapsToUnknown(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	defer ts.Close()
	in := []Finding{secret("OpenAI API key", "sk-proj-anykey0123456789abcdef0123456789ab")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationUnknown {
		t.Errorf("expected unknown on 5xx, got %+v", got)
	}
}

func TestVerifyFindings_DedupesSameKey(t *testing.T) {
	var calls atomic.Int32
	ts := stubServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	})
	defer ts.Close()
	const key = "sk-proj-sharedkey0123456789abcdef0123456789ab"
	in := []Finding{
		secret("OpenAI API key", key),
		secret("OpenAI API key", key),
		secret("OpenAI API key", key),
		secret("OpenAI API key", key),
	}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 network call for 4 findings of same key, got %d", got)
	}
	for i, f := range out {
		if f.Verification == nil || f.Verification.Status != VerificationValid {
			t.Errorf("finding %d: expected valid, got %+v", i, f.Verification)
		}
	}
}

func TestVerifyFindings_TimeoutMapsToUnknown(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// Sleep past the per-call timeout; the verifier should give up
		// and surface unknown rather than blocking forever.
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(200)
	})
	defer ts.Close()
	in := []Finding{secret("OpenAI API key", "sk-proj-anykey0123456789abcdef0123456789ab")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:     rewriteClient(t, ts),
		RatePerSecond:  100,
		TimeoutPerCall: 25 * time.Millisecond,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationUnknown {
		t.Errorf("expected unknown on timeout, got %+v", got)
	}
}

func TestVerifyFindings_PatternWithoutVerifier(t *testing.T) {
	// `High-entropy string near credential keyword` isn't in
	// providersByLabel — should still produce a verification record with
	// status=unknown, not a silent gap.
	in := []Finding{secret("High-entropy string near credential keyword", "abc123def456")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationUnknown {
		t.Errorf("expected unknown for unmapped pattern, got %+v", got)
	}
	if !strings.Contains(out[0].Verification.Reason, "no verifier") {
		t.Errorf("expected reason to mention 'no verifier', got %q", out[0].Verification.Reason)
	}
}

func TestVerifyFindings_GitLab_PrivateTokenHeader(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") == "" {
			t.Error("gitlab verifier must send PRIVATE-TOKEN header")
		}
		w.WriteHeader(200)
	})
	defer ts.Close()
	in := []Finding{secret("GitLab personal access token", "glpat-validvalidvalidvalidvalid")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationValid {
		t.Errorf("expected valid, got %+v", got)
	}
}

func TestVerifyFindings_Npm_BearerWhoami(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/-/whoami" {
			t.Errorf("npm verifier hit %s, expected /-/whoami", r.URL.Path)
		}
		w.WriteHeader(401)
	})
	defer ts.Close()
	in := []Finding{secret("npm access token", "npm_rejectedtokenaaaaaaaaaaaaaaaaaaaaaaaa")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationInvalid {
		t.Errorf("expected invalid, got %+v", got)
	}
}

func TestVerifyFindings_SendGrid_BearerScopes(t *testing.T) {
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/scopes" {
			t.Errorf("sendgrid verifier hit %s, expected /v3/scopes", r.URL.Path)
		}
		w.WriteHeader(200)
	})
	defer ts.Close()
	in := []Finding{secret("SendGrid API key", "SG.validvalidvalid.validvalidvalid01")}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationValid {
		t.Errorf("expected valid, got %+v", got)
	}
}

func TestVerifyFindings_Slack_OkTrueValid_OkFalseInvalid(t *testing.T) {
	// Slack returns 200 either way; body's `ok` carries the verdict.
	// One token has "good" in it (→ ok:true), the other doesn't (→ ok:false).
	const goodKey = "xoxb-good-1234567890-aaaaaaaaaa"
	const badKey = "xoxb-bad-1234567890-bbbbbbbbbb"
	ts := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("slack verifier must use Bearer auth")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if strings.Contains(r.Header.Get("Authorization"), goodKey) {
			_, _ = w.Write([]byte(`{"ok":true,"user":"U123","team":"T123"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	})
	defer ts.Close()
	in := []Finding{
		secret("Slack token", goodKey),
		secret("Slack token", badKey),
	}
	out := VerifyFindings(context.Background(), in, VerifyOptions{
		HTTPClient:    rewriteClient(t, ts),
		RatePerSecond: 100,
	})
	if got := out[0].Verification; got == nil || got.Status != VerificationValid {
		t.Errorf("expected ok=true valid, got %+v", got)
	}
	if got := out[1].Verification; got == nil || got.Status != VerificationInvalid {
		t.Errorf("expected ok=false invalid, got %+v", got)
	}
}

func TestVerifyFindings_NonSecretsPassThrough(t *testing.T) {
	in := []Finding{
		{
			FilePath: "src/x.ts", LineStart: 1, LineEnd: 1,
			Category: "sql-injection", Severity: "critical",
			Title: "x", Explanation: "x", ContentHash: "x",
		},
	}
	out := VerifyFindings(context.Background(), in, VerifyOptions{RatePerSecond: 100})
	if out[0].Verification != nil {
		t.Errorf("non-secret finding should have nil Verification, got %+v", out[0].Verification)
	}
}
