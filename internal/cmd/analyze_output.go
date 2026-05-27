package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/getdebug-ai/cli/internal/report"
	"github.com/getdebug-ai/cli/internal/scan"
)

// systemDirPrefixes is a small, conservative deny-list of paths the CLI
// should refuse to write SARIF into. The threat model is a malicious
// PR setting `--sarif=/etc/cron.d/x` in a CI workflow that runs as a
// user with surprising privileges (a self-hosted runner mounted with
// /etc writable, a container-escape, etc). Standard hosted CI runners
// can't actually write to these paths so the cost of the check is zero
// and the upside is a loud, early refusal rather than a confusing
// permission-denied at rename time.
var systemDirPrefixes = []string{
	"/etc/",
	"/bin/",
	"/sbin/",
	"/usr/bin/",
	"/usr/sbin/",
	"/boot/",
	"/proc/",
	"/sys/",
}

func validateSARIFPath(path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	clean := filepath.Clean(path)
	// Reject writes into known-sensitive system dirs.
	for _, p := range systemDirPrefixes {
		if strings.HasPrefix(clean, p) {
			return fmt.Errorf("refusing to write SARIF under %s", p)
		}
	}
	// Refuse to overwrite a symlink — the target may not be where the
	// caller thinks. Atomically writing to `path + ".tmp"` is fine; the
	// final `os.Rename` would follow the symlink at the destination.
	if info, err := os.Lstat(clean); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink: %s", clean)
	}
	return nil
}

// writeSARIFFile writes a SARIF log atomically: write to a sibling .tmp
// and rename, so a partial write never leaves a half-formed file for the
// next pipeline step (e.g. github/codeql-action/upload-sarif) to choke on.
func writeSARIFFile(path string, findings []scan.Finding) error {
	if err := validateSARIFPath(path); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := report.WriteSARIF(f, findings, version); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// writeNDJSON emits one finding per line. Stable for piping into jq, GitHub
// annotations, or whatever the user's pipeline wants.
func writeNDJSON(w io.Writer, findings []scan.Finding) error {
	enc := json.NewEncoder(w)
	for i := range findings {
		if err := enc.Encode(findings[i]); err != nil {
			return err
		}
	}
	return nil
}
