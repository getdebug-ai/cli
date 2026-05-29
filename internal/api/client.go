// Package api is the HTTP client the CLI uses to talk to the getdebug backend.
// Phase 1 stub — concrete methods land alongside the API routes.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client holds the base URL + auth token for the getdebug API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// ErrInsecureBaseURL is returned when a non-https URL is supplied without
// a loopback host. The CLI's device-flow code and bearer token are too
// sensitive to send in the clear, and a phishing pitch ("use --api
// http://staging.attacker.example") otherwise lets the attacker collect
// freshly minted tokens.
var ErrInsecureBaseURL = errors.New("api base URL must be https:// (http allowed only for localhost/127.0.0.1)")

// New returns a Client with sensible defaults.
//
// Returns ErrInsecureBaseURL if baseURL is an http:// URL pointing at a
// non-loopback host. Callers that want the old "trust whatever URL" shape
// for tests can use NewUnsafe.
func New(baseURL, token string) (*Client, error) {
	if err := validateBaseURL(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// NewUnsafe skips the https check. Intended for unit tests that spin up
// a local httptest.Server. Do not use in production code paths.
func NewUnsafe(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func validateBaseURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse base url: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" {
		return fmt.Errorf("%w: scheme=%q", ErrInsecureBaseURL, u.Scheme)
	}
	// http allowed for loopback dev servers only — strip the port to compare.
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil
	}
	return fmt.Errorf("%w: host=%q", ErrInsecureBaseURL, host)
}

// envelope mirrors the API's {ok:true,data} | {ok:false,error} shape.
type envelope[T any] struct {
	OK    bool `json:"ok"`
	Data  T    `json:"data,omitempty"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Do issues an HTTP request and decodes the envelope into out (if non-nil).
// Returns an error built from the envelope's error block on non-ok responses.
func (c *Client) Do(req *http.Request, out any) error {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var env envelope[json.RawMessage]
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("decode envelope: %w (body=%s)", err, string(body))
	}

	if !env.OK {
		if env.Error == nil {
			return errors.New("api: unknown error")
		}
		return fmt.Errorf("api: %s: %s", env.Error.Code, env.Error.Message)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}
	return nil
}
