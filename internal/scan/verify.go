// Secret verification — Go port of workers/src/security/verify.ts.
//
// Promotes "this looks like an API key" to "this IS an API key" by
// making one authenticated GET against the provider's whoami-shaped
// endpoint and reading the status code. Same shape trufflehog ships
// as `--only-verified`, and the single biggest noise reduction the
// industry-paid secret scanners offer over the open-source ones.
//
// Coverage today mirrors the TS side: OpenAI, Anthropic, xAI, GitHub
// (classic + fine-grained PAT), Stripe, Paystack. Every endpoint is
// read-only / GET-shaped — we never POST a message or charge
// anything. Status mapping is deterministic:
//
//   • 2xx        → "valid"
//   • 401, 403   → "invalid"   (definitive rejection by the provider)
//   • else       → "unknown"   (5xx, 429, timeout, network error)
//
// Findings are NEVER dropped here. Verification adds a Verification
// record on the Finding; the dashboard / CI gate decide what to do
// with the result. The `--only-verified` analyze flag is what filters
// `invalid` out of the surfaced set.

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VerificationStatus is the three-state outcome of a provider check.
type VerificationStatus string

const (
	VerificationValid   VerificationStatus = "valid"
	VerificationInvalid VerificationStatus = "invalid"
	VerificationUnknown VerificationStatus = "unknown"
)

// Verification is the record attached to a Finding after the
// verification pass runs. Mirrors the TS shape so the SARIF / JSON
// exporters can round-trip without translation.
type Verification struct {
	Status     VerificationStatus `json:"status"`
	Reason     string             `json:"reason"`
	Provider   string             `json:"provider"`
	VerifiedAt string             `json:"verifiedAt"`
}

// verifier is the per-provider request shape. Each implementation
// fires ONE request and returns its raw HTTP status (or an error if
// the call didn't complete). status → result is mapped uniformly.
type verifier func(ctx context.Context, client *http.Client, key string) (int, error)

// providerVerifier pairs an id (used in the badge + filter) with the
// request function.
type providerVerifier struct {
	id     string
	verify verifier
}

// providersByLabel maps the pattern label on the Finding (set by the
// regex pass — see regexPatterns) to its verifier. Labels not in this
// map fall through to "unknown" status with reason "no verifier for
// this pattern" — surfacing the gap honestly rather than silently
// dropping the row.
var providersByLabel = map[string]providerVerifier{
	"OpenAI API key":               {id: "openai", verify: verifyOpenAI},
	"Anthropic API key":            {id: "anthropic", verify: verifyAnthropic},
	"xAI API key":                  {id: "xai", verify: verifyXAI},
	"GitHub PAT (classic)":         {id: "github", verify: verifyGitHub},
	"GitHub fine-grained PAT":      {id: "github", verify: verifyGitHub},
	"Stripe secret key":            {id: "stripe", verify: verifyStripe},
	"Stripe restricted key":        {id: "stripe", verify: verifyStripe},
	"Paystack secret key":          {id: "paystack", verify: verifyPaystack},
	"GitLab personal access token": {id: "gitlab", verify: verifyGitLab},
	"npm access token":             {id: "npm", verify: verifyNpm},
	"SendGrid API key":             {id: "sendgrid", verify: verifySendGrid},
	"Slack token":                  {id: "slack", verify: verifySlack},
}

// ── Per-provider verifiers ─────────────────────────────────────────

const userAgent = "getdebug-verifier"

func verifyOpenAI(ctx context.Context, c *http.Client, key string) (int, error) {
	return bearerGet(ctx, c, "https://api.openai.com/v1/models", key)
}

func verifyAnthropic(ctx context.Context, c *http.Client, key string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.anthropic.com/v1/messages/batches?limit=1", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("User-Agent", userAgent)
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return res.StatusCode, nil
}

func verifyXAI(ctx context.Context, c *http.Client, key string) (int, error) {
	return bearerGet(ctx, c, "https://api.x.ai/v1/models", key)
}

func verifyGitHub(ctx context.Context, c *http.Client, key string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/user", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return res.StatusCode, nil
}

func verifyStripe(ctx context.Context, c *http.Client, key string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return 0, err
	}
	// Stripe uses HTTP basic with the secret key as the user and no password.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(key+":")))
	req.Header.Set("User-Agent", userAgent)
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return res.StatusCode, nil
}

func verifyPaystack(ctx context.Context, c *http.Client, key string) (int, error) {
	return bearerGet(ctx, c, "https://api.paystack.co/balance", key)
}

// verifyGitLab — GitLab PAT identity check via the `PRIVATE-TOKEN`
// header convention. Returns 200 for valid, 401 for invalid.
func verifyGitLab(ctx context.Context, c *http.Client, key string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://gitlab.com/api/v4/user", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", key)
	req.Header.Set("User-Agent", userAgent)
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return res.StatusCode, nil
}

func verifyNpm(ctx context.Context, c *http.Client, key string) (int, error) {
	return bearerGet(ctx, c, "https://registry.npmjs.org/-/whoami", key)
}

func verifySendGrid(ctx context.Context, c *http.Client, key string) (int, error) {
	return bearerGet(ctx, c, "https://api.sendgrid.com/v3/scopes", key)
}

// slackResponse is the read-from-body shape verifySlack needs. Slack
// returns 200 even for rejected tokens; the `ok` field is what carries
// the decision.
type slackResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// verifySlack is the one provider whose status code isn't enough — Slack
// returns 200 for both valid and invalid tokens, with `ok` in the body
// carrying the actual decision. We surface a sentinel status code so the
// shared mapAuthStatus does the right thing, but the per-provider
// VerifyFindings caller dispatches on the body when status==200. The
// caller in this file lives in the main verifier flow; we expose the
// body-read here as a separate path that returns a status code
// callers can map: 200 = ok, 401 = ok-false, anything else = unmapped.
func verifySlack(ctx context.Context, c *http.Client, key string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://slack.com/api/auth.test", strings.NewReader(""))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res.StatusCode, nil
	}
	var body slackResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("slack body decode: %w", err)
	}
	if body.OK {
		return http.StatusOK, nil
	}
	// Reuse the 401 mapping path for `ok=false` — Slack treats this as a
	// rejection of the token, just shaped differently from a normal 401.
	return http.StatusUnauthorized, nil
}

// bearerGet — the common shape for OpenAI / xAI / Paystack.
func bearerGet(ctx context.Context, c *http.Client, url, key string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", userAgent)
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return res.StatusCode, nil
}

// ── Rate limiter ───────────────────────────────────────────────────

// rateLimiter throttles to N tokens per second. One limiter per
// provider — different providers run independently so a slow one
// can't stall another. Tiny channel-based implementation; the buffer
// holds the burst.
type rateLimiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newRateLimiter(perSecond int) *rateLimiter {
	if perSecond <= 0 {
		perSecond = 1
	}
	rl := &rateLimiter{
		tokens: make(chan struct{}, perSecond),
		stop:   make(chan struct{}),
	}
	for i := 0; i < perSecond; i++ {
		rl.tokens <- struct{}{}
	}
	interval := time.Second / time.Duration(perSecond)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-rl.stop:
				return
			case <-t.C:
				select {
				case rl.tokens <- struct{}{}:
				default: // full bucket; drop the refill
				}
			}
		}
	}()
	return rl
}

func (rl *rateLimiter) Acquire(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rl *rateLimiter) Close() { close(rl.stop) }

// ── Public entry point ────────────────────────────────────────────

// VerifyOptions controls one VerifyFindings call.
type VerifyOptions struct {
	// TimeoutPerCall caps each provider request. Default 5s.
	TimeoutPerCall time.Duration
	// RatePerSecond caps each provider's request rate. Default 5.
	RatePerSecond int
	// HTTPClient lets tests inject a stub. Default = http.DefaultClient
	// with the timeout set on the per-request context.
	HTTPClient *http.Client
}

// VerifyFindings annotates every secrets finding with a Verification
// record. Findings whose pattern has no verifier still get a record
// with status=unknown — never a silent gap. Concurrent: up to
// RatePerSecond outstanding requests per provider; one network call
// per distinct (provider, key) tuple even if the key appears in many
// files.
func VerifyFindings(ctx context.Context, findings []Finding, opts VerifyOptions) []Finding {
	if opts.TimeoutPerCall == 0 {
		opts.TimeoutPerCall = 5 * time.Second
	}
	if opts.RatePerSecond == 0 {
		opts.RatePerSecond = 5
	}
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	// Per-provider limiter pool.
	var limMu sync.Mutex
	limiters := map[string]*rateLimiter{}
	limiterFor := func(id string) *rateLimiter {
		limMu.Lock()
		defer limMu.Unlock()
		l := limiters[id]
		if l == nil {
			l = newRateLimiter(opts.RatePerSecond)
			limiters[id] = l
		}
		return l
	}
	defer func() {
		for _, l := range limiters {
			l.Close()
		}
	}()

	// Per-key cache. Stores a channel that closes once the result is
	// ready — concurrent callers with the same key wait on the same
	// channel instead of racing the verifier.
	type cacheEntry struct {
		done   chan struct{}
		result Verification
	}
	var cacheMu sync.Mutex
	cache := map[string]*cacheEntry{}

	out := make([]Finding, len(findings))
	var wg sync.WaitGroup
	wg.Add(len(findings))
	for i := range findings {
		i := i
		f := findings[i]
		out[i] = f
		go func() {
			defer wg.Done()
			if f.Category != "secrets" {
				return
			}
			provider, has := providersByLabel[f.Pattern]
			if !has {
				out[i].Verification = &Verification{
					Status:     VerificationUnknown,
					Reason:     "no verifier for this pattern",
					Provider:   providerIDFromLabel(f.Pattern),
					VerifiedAt: time.Now().UTC().Format(time.RFC3339),
				}
				return
			}
			if f.Snippet == "" {
				out[i].Verification = &Verification{
					Status:     VerificationUnknown,
					Reason:     "finding has no captured value to verify",
					Provider:   provider.id,
					VerifiedAt: time.Now().UTC().Format(time.RFC3339),
				}
				return
			}
			cacheKey := provider.id + "::" + shortHash(f.Snippet)

			// Dedupe: first caller for this key owns the verification;
			// later ones wait on the shared channel.
			cacheMu.Lock()
			entry, exists := cache[cacheKey]
			if !exists {
				entry = &cacheEntry{done: make(chan struct{})}
				cache[cacheKey] = entry
			}
			cacheMu.Unlock()
			if exists {
				<-entry.done
				out[i].Verification = &Verification{
					Status:     entry.result.Status,
					Reason:     entry.result.Reason,
					Provider:   entry.result.Provider,
					VerifiedAt: entry.result.VerifiedAt,
				}
				return
			}

			if err := limiterFor(provider.id).Acquire(ctx); err != nil {
				entry.result = Verification{
					Status:     VerificationUnknown,
					Reason:     "verifier cancelled before rate-limit acquire: " + err.Error(),
					Provider:   provider.id,
					VerifiedAt: time.Now().UTC().Format(time.RFC3339),
				}
				close(entry.done)
				out[i].Verification = &entry.result
				return
			}

			callCtx, cancel := context.WithTimeout(ctx, opts.TimeoutPerCall)
			status, err := provider.verify(callCtx, client, f.Snippet)
			cancel()
			entry.result = mapAuthStatus(status, provider.id, err)
			close(entry.done)
			out[i].Verification = &entry.result
		}()
	}
	wg.Wait()
	return out
}

func mapAuthStatus(status int, provider string, callErr error) Verification {
	now := time.Now().UTC().Format(time.RFC3339)
	if callErr != nil {
		reason := "verifier network error: " + callErr.Error()
		if errors.Is(callErr, context.DeadlineExceeded) {
			reason = "verifier timed out"
		}
		return Verification{Status: VerificationUnknown, Reason: reason, Provider: provider, VerifiedAt: now}
	}
	if status >= 200 && status < 300 {
		return Verification{Status: VerificationValid, Reason: fmt.Sprintf("provider returned %d", status), Provider: provider, VerifiedAt: now}
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return Verification{Status: VerificationInvalid, Reason: fmt.Sprintf("provider rejected key (HTTP %d)", status), Provider: provider, VerifiedAt: now}
	}
	return Verification{
		Status:     VerificationUnknown,
		Reason:     fmt.Sprintf("provider returned %d — could not determine validity", status),
		Provider:   provider,
		VerifiedAt: now,
	}
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

func providerIDFromLabel(label string) string {
	// Best-effort first-word lowercase for the badge.
	for i, r := range label {
		if r == ' ' {
			return lower(label[:i])
		}
	}
	return lower(label)
}

func lower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
