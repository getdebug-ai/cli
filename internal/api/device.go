// Device-flow client for `getdebug login`.
//
// RFC 8628 shape:
//   1. RequestDeviceCode → server hands back a pair (deviceCode is the
//      polling secret; userCode is what the user types into the browser).
//   2. PollToken until the user approves (response: token + userEmail) or
//      we time out / they deny / it expires. Honour the server-side
//      slow_down by doubling the interval up to MaxPollInterval.
//
// The plaintext deviceCode is treated like a credential — it lives in
// memory for the duration of `login` and is never written to disk.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DeviceCodeRequest is the body for POST /v1/auth/device/code.
type DeviceCodeRequest struct {
	ClientName string `json:"clientName,omitempty"`
}

// DeviceCodeResponse is the data block returned by POST /v1/auth/device/code.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURL         string `json:"verificationUrl"`
	VerificationURLComplete string `json:"verificationUrlComplete"`
	ExpiresIn               int    `json:"expiresIn"` // seconds
	Interval                int    `json:"interval"`  // seconds between polls
}

// DeviceTokenResponse is the data block returned by POST /v1/auth/device/token
// once the user has approved.
type DeviceTokenResponse struct {
	Token     string `json:"token"`
	TokenID   string `json:"tokenId"`
	UserEmail string `json:"userEmail"`
}

// ErrAuthorizationPending is returned by PollToken on every "still waiting"
// poll. Callers loop until they see one of the terminal errors below or
// success.
var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrExpiredToken         = errors.New("expired_token")
	ErrAccessDenied         = errors.New("access_denied")
)

// RequestDeviceCode kicks off the device flow.
func (c *Client) RequestDeviceCode(ctx context.Context, clientName string) (*DeviceCodeResponse, error) {
	body, err := json.Marshal(DeviceCodeRequest{ClientName: clientName})
	if err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/auth/device/code", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var out DeviceCodeResponse
	if err := c.Do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PollOnce does one POST /v1/auth/device/token call and returns the parsed
// response, mapping the documented error codes to typed errors. Callers
// drive the loop themselves so they can show progress.
func (c *Client) PollOnce(ctx context.Context, deviceCode string) (*DeviceTokenResponse, error) {
	body, err := json.Marshal(struct {
		DeviceCode string `json:"deviceCode"`
	}{DeviceCode: deviceCode})
	if err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/auth/device/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// We can't use c.Do here because we need to distinguish the documented
	// error codes (which arrive as ok:false envelopes with a specific code)
	// from network failures and from success. Inline the envelope decode.
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var env struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data,omitempty"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w (body=%s)", err, string(raw))
	}

	if !env.OK {
		if env.Error == nil {
			return nil, fmt.Errorf("api: unknown error (status=%d)", res.StatusCode)
		}
		switch env.Error.Code {
		case "authorization_pending":
			return nil, ErrAuthorizationPending
		case "slow_down":
			return nil, ErrSlowDown
		case "expired_token":
			return nil, ErrExpiredToken
		case "access_denied":
			return nil, ErrAccessDenied
		default:
			return nil, fmt.Errorf("api: %s: %s", env.Error.Code, env.Error.Message)
		}
	}

	var out DeviceTokenResponse
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("decode data: %w", err)
	}
	return &out, nil
}

// PollUntilApproved repeatedly calls PollOnce honouring the slow_down /
// pending semantics. progress is invoked on each tick so the CLI can update
// the spinner. Returns the token response on approval, or a terminal error.
//
// Defence against a compromised / hostile backend that returns slow_down
// indefinitely to keep the login hanging: cap consecutive slow_down
// responses, then bail with ErrSlowDown so the user gets a clear error
// instead of a forever-pinwheel. The context deadline is the outer
// bound; this is the inner one so a hostile server can't soak the full
// 10-minute device-code TTL waiting for the user to give up.
func (c *Client) PollUntilApproved(
	ctx context.Context,
	deviceCode string,
	interval time.Duration,
	maxInterval time.Duration,
	progress func(),
) (*DeviceTokenResponse, error) {
	const maxConsecutiveSlowDown = 5
	current := interval
	slowDownStreak := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(current):
		}
		if progress != nil {
			progress()
		}
		resp, err := c.PollOnce(ctx, deviceCode)
		if err == nil {
			return resp, nil
		}
		switch {
		case errors.Is(err, ErrAuthorizationPending):
			// keep current interval
			slowDownStreak = 0
		case errors.Is(err, ErrSlowDown):
			slowDownStreak++
			if slowDownStreak >= maxConsecutiveSlowDown {
				return nil, fmt.Errorf("server kept asking us to slow down (%d times); aborting login: %w",
					slowDownStreak, ErrSlowDown)
			}
			current *= 2
			if current > maxInterval {
				current = maxInterval
			}
		default:
			return nil, err
		}
	}
}
