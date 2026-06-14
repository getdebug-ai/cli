package cmd

import "testing"

// FIX 14 (2026-06-06 dogfood): defaultAPIBaseURL must NOT inherit a
// localhost API base from a prior dev login. The previous behaviour
// silently handed `http://localhost:4000` (left over from local dev) to
// every subsequent `getdebug login`, then quietly failed to reach prod.
func TestIsLocalhostURL_DetectsCommonLocalShapes(t *testing.T) {
	cases := []struct {
		url      string
		want     bool
	}{
		{"http://localhost:4000", true},
		{"http://localhost", true},
		{"https://localhost:8443", true},
		{"http://127.0.0.1:4000", true},
		{"http://0.0.0.0:4000", true},
		{"https://[::1]:4000", true},
		{"HTTP://LOCALHOST:4000", true}, // case-insensitive
		{"  http://localhost:4000  ", true}, // whitespace-tolerant

		// Prod / staging URLs must NOT be classified as localhost.
		{"https://api.getdebug.dev", false},
		{"https://staging.api.getdebug.dev", false},
		{"https://my-tunnel.ngrok-free.app", false},
		// A hostname that merely starts with "local" is not localhost.
		{"https://local-clone.getdebug.dev", false},
		// Plausible adversarial — looks loopback-ish but isn't.
		{"https://127.0.0.1.evil.example", false},
		// Empty string handled (defaultAPIBaseURL guards on it anyway).
		{"", false},
	}
	for _, tc := range cases {
		if got := isLocalhostURL(tc.url); got != tc.want {
			t.Errorf("isLocalhostURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
