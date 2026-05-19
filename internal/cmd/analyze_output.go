package cmd

import (
	"encoding/json"
	"io"
	"os"

	"github.com/getdebug-ai/cli/internal/report"
	"github.com/getdebug-ai/cli/internal/scan"
)

// writeSARIFFile writes a SARIF log atomically: write to a sibling .tmp
// and rename, so a partial write never leaves a half-formed file for the
// next pipeline step (e.g. github/codeql-action/upload-sarif) to choke on.
func writeSARIFFile(path string, findings []scan.Finding) error {
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
