// Package api is the HTTP client the CLI uses to talk to the getdebug backend.
// Phase 1 stub — concrete methods land alongside the API routes.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client holds the base URL + auth token for the getdebug API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a Client with sensible defaults.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
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
