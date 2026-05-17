// Package config loads + writes the CLI config at ~/.getdebug/config.json.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Config holds the CLI's persistent state. Tokens live here; the user can
// delete the file to log out.
type Config struct {
	APIBaseURL string `json:"apiBaseUrl,omitempty"`
	Token      string `json:"token,omitempty"`
	UserEmail  string `json:"userEmail,omitempty"`
}

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
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
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
