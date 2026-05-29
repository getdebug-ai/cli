package api

import (
	"errors"
	"testing"
)

func TestNew_AcceptsHTTPS(t *testing.T) {
	cases := []string{
		"https://api.getdebug.dev",
		"https://api.getdebug.dev:443",
		"https://api.getdebug.dev/v1",
		"https://staging.example.com",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			c, err := New(u, "tok")
			if err != nil {
				t.Errorf("New(%q) = %v, want nil", u, err)
			}
			if c == nil {
				t.Error("New returned nil client without error")
			}
		})
	}
}

func TestNew_AcceptsLoopbackHTTP(t *testing.T) {
	// http allowed only for loopback — local-dev convenience. Anything
	// else is a phishing vector ("use --api http://staging-attacker.com")
	// and must be refused.
	cases := []string{
		"http://localhost:3000",
		"http://localhost",
		"http://127.0.0.1",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if _, err := New(u, ""); err != nil {
				t.Errorf("New(%q) = %v, want nil", u, err)
			}
		})
	}
}

func TestNew_RejectsInsecureRemote(t *testing.T) {
	// Each of these is the kind of URL a phishing pitch would put in
	// front of a user. Refuse loudly — the device-flow token would
	// otherwise be exchanged in cleartext.
	cases := []string{
		"http://api.getdebug.dev",
		"http://staging.example.com",
		"http://198.51.100.7",
		"http://attacker.local",
		"http://api.getdebug.dev:80",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			_, err := New(u, "")
			if err == nil {
				t.Fatalf("New(%q) = nil, want ErrInsecureBaseURL", u)
			}
			if !errors.Is(err, ErrInsecureBaseURL) {
				t.Errorf("error = %v, want ErrInsecureBaseURL", err)
			}
		})
	}
}

func TestNew_RejectsExoticSchemes(t *testing.T) {
	// Not https, not http — schemes like file:// or ftp:// have no
	// business being a getdebug API base.
	cases := []string{
		"file:///etc/passwd",
		"ftp://api.example.com",
		"javascript:alert(1)",
		"data:text/plain,hi",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if _, err := New(u, ""); err == nil {
				t.Fatalf("New(%q) = nil, want error", u)
			}
		})
	}
}

func TestNewUnsafe_BypassesValidation(t *testing.T) {
	// NewUnsafe exists for test setups that spin up httptest.Server —
	// confirm it accepts a plain http URL without erroring.
	c := NewUnsafe("http://127.0.0.1:1/test-server", "")
	if c == nil {
		t.Fatal("NewUnsafe returned nil")
	}
}
