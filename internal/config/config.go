// Package config loads + writes the CLI config at ~/.getdebug/config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds the CLI's persistent state. Tokens live here; the user can
// delete the file to log out.
type Config struct {
	APIBaseURL string `json:"apiBaseUrl,omitempty"`
	Token      string `json:"token,omitempty"`
	UserEmail  string `json:"userEmail,omitempty"`
}

// ErrInsecurePerms is returned when the config file exists but has
// group/other read bits set. The token in this file is a long-lived
// bearer credential — any local process running as another user could
// pick it up. Refuse to use it until the user re-secures the file.
var ErrInsecurePerms = errors.New("config file has insecure permissions; run `chmod 600 ~/.getdebug/config.json`")

// Path returns the path to the on-disk config file (creating parent dirs if missing).
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".getdebug")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the config. Returns an empty Config (not an error) when the file
// doesn't exist — the caller decides whether that's a problem.
//
// If the file exists with group/other bits set (and we're on a Unix-like
// OS where those bits mean what we think they mean), the load fails with
// ErrInsecurePerms — better a loud error than silently using a token
// any local process can scrape.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(p)
		if err == nil {
			if mode := st.Mode().Perm(); mode&0o077 != 0 {
				return nil, fmt.Errorf("%w (current: %o, expected: 0600)", ErrInsecurePerms, mode)
			}
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the config atomically, mode 0600.
func Save(c *Config) error {
	p, err := Path()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
