// Local SAST via Ollama chat — the AI half of `getdebug analyze --local-llm`.
//
// Until now the CLI's local analyze shipped only the regex/entropy secrets
// detector (this file's sibling, secrets.go); LLM-based SAST required
// uploading to the hosted API. This adds the analysis pass to the local
// path: walk source, send each eligible file to the user's Ollama model
// (Qwen / DeepSeek / Llama, their choice), parse a JSON findings array,
// surface as the same Finding shape the secrets pass uses. Code never
// leaves the laptop. No API key, no spend.
//
// Honest degradation: a malformed model response is logged + dropped — we
// don't fabricate findings. Per-scan call cap bounds wall-clock so
// `analyze --local-llm` doesn't hang on a huge repo with a slow local model.

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getdebug-ai/cli/internal/localllm"
)

// SastLocalOptions configures one local-SAST pass.
type SastLocalOptions struct {
	Workdir string
	Client  *localllm.Client
	Model   string
	// MaxFiles caps the per-scan call count. Local 7B models on CPU run
	// 30s–5min per file; without this, a 500-file repo could pin the
	// laptop for hours. Default 50.
	MaxFiles int
	// MaxFileBytes skips oversize files (generated, vendored, lockfiles).
	// Default 96 KiB — large enough for almost every hand-written source
	// file, small enough that the model's context window isn't a problem.
	MaxFileBytes int
	// Logf is an optional progress logger (printed to stderr by the CLI).
	Logf func(format string, args ...any)
}

// SastLocalResult summarises what the pass covered + emitted.
type SastLocalResult struct {
	Findings        []Finding
	FilesConsidered int
	FilesScanned    int
	FilesSkipped    int // oversize / unreadable
	Malformed       int // model responses we couldn't parse
	Errors          int // transport / model errors
}

// Same languages the worker's SAST pass supports (TS/JS/TSX/JSX/Python/Go).
// Other extensions are walked but skipped — the model's signal-to-noise on
// non-source / unknown-language content is too low to justify the call.
var sastLangExts = map[string]struct{}{
	".ts":  {},
	".tsx": {},
	".js":  {},
	".jsx": {},
	".mjs": {},
	".cjs": {},
	".py":  {},
	".go":  {},
}

// One-line per-finding minimum confidence we'll surface. Mirrors the
// workers holistic pass's MIN_CONFIDENCE.
const sastLocalMinConfidence = 0.6

// SAST categories the model is asked to flag. Same set the hosted detector
// covers, sans 'secrets' (already handled by the regex pass).
var sastLocalCategories = []string{
	"sql-injection",
	"command-injection",
	"path-traversal",
	"xss",
	"ssrf",
	"insecure-deserialize",
	"weak-crypto",
	"insecure-random",
	"missing-auth",
	"broken-access",
	"open-redirect",
	"insecure-cors",
}

// OWASP/CWE references — populated for surfaced findings so the local
// output matches the shape the hosted dashboard renders.
var sastLocalCWE = map[string]string{
	"sql-injection":        "CWE-89",
	"command-injection":    "CWE-78",
	"path-traversal":       "CWE-22",
	"xss":                  "CWE-79",
	"ssrf":                 "CWE-918",
	"insecure-deserialize": "CWE-502",
	"weak-crypto":          "CWE-327",
	"insecure-random":      "CWE-338",
	"missing-auth":         "CWE-862",
	"broken-access":        "CWE-863",
	"open-redirect":        "CWE-601",
	"insecure-cors":        "CWE-942",
}

var sastLocalOWASP = map[string]string{
	"sql-injection":        "A03:2021",
	"command-injection":    "A03:2021",
	"path-traversal":       "A01:2021",
	"xss":                  "A03:2021",
	"ssrf":                 "A10:2021",
	"insecure-deserialize": "A08:2021",
	"weak-crypto":          "A02:2021",
	"insecure-random":      "A02:2021",
	"missing-auth":         "A01:2021",
	"broken-access":        "A01:2021",
	"open-redirect":        "A01:2021",
	"insecure-cors":        "A05:2021",
}

// systemPrompt is the standing instruction handed to the model on every
// call. Kept short — small local models follow concise instructions better
// than the hosted prompts which can afford to elaborate.
func sastLocalSystemPrompt() string {
	cats := strings.Join(sastLocalCategories, ", ")
	return strings.Join([]string{
		"You are a security reviewer auditing one source file.",
		"Flag only issues matching these categories: " + cats + ".",
		"Respond with STRICT JSON, no markdown fences, no prose:",
		`{"findings":[{"lineStart":<int>,"lineEnd":<int>,"category":"<one of the above>",` +
			`"severity":"critical|high|medium|low|info","title":"<short>","explanation":"<why it is a risk>",` +
			`"confidence":<0-1>}]}`,
		"Rules:",
		"- Line numbers refer to the file content shown below (1-based).",
		"- Be calibrated: a false positive costs more trust than a missed finding.",
		`- An empty array is a valid, good answer: {"findings":[]}.`,
		"- Skip findings outside the listed categories.",
	}, "\n")
}

// modelResponse is what we ask the model to produce.
type modelResponse struct {
	Findings []modelFinding `json:"findings"`
}

type modelFinding struct {
	LineStart   int     `json:"lineStart"`
	LineEnd     int     `json:"lineEnd"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Explanation string  `json:"explanation"`
	Confidence  float64 `json:"confidence"`
}

// ScanSastLocal runs the local SAST pass over Workdir. Returns the
// findings alongside the coverage counters so the CLI can render an
// honest "scanned N of M, dropped K malformed" footer (mirroring how the
// hosted dashboard surfaces SAST coverage).
func ScanSastLocal(ctx context.Context, opts SastLocalOptions) (*SastLocalResult, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 50
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 96 * 1024
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("ScanSastLocal: nil Ollama client")
	}
	model := opts.Model
	if model == "" {
		model = localllm.DefaultModel
	}

	system := sastLocalSystemPrompt()
	res := &SastLocalResult{Findings: []Finding{}}

	// Walk eligible files first so we know the universe before deciding
	// what to send to the model. Stops at MaxFiles — surplus files are
	// counted in FilesConsidered but never opened.
	type candidate struct{ abs, rel string }
	var candidates []candidate
	err := filepath.WalkDir(opts.Workdir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable subtrees, don't abort the whole scan
		}
		if d.IsDir() {
			name := d.Name()
			if _, skip := skipDirs[name]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := sastLangExts[ext]; !ok {
			return nil
		}
		rel, _ := filepath.Rel(opts.Workdir, path)
		// Mirror the secrets pass: skip tests + test-dirs (high false-fire
		// rate, the model wastes calls).
		if testFile.MatchString(rel) || testDir.MatchString(rel) {
			return nil
		}
		res.FilesConsidered++
		candidates = append(candidates, candidate{abs: path, rel: rel})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", opts.Workdir, err)
	}

	if len(candidates) == 0 {
		return res, nil
	}

	for i, c := range candidates {
		if i >= opts.MaxFiles {
			break
		}
		raw, err := os.ReadFile(c.abs)
		if err != nil {
			res.FilesSkipped++
			continue
		}
		if len(raw) > opts.MaxFileBytes {
			res.FilesSkipped++
			continue
		}
		// Inject 1-based line numbers so the model can reference them in
		// its response. Same shape the hosted holistic pass uses.
		numbered := numberLines(string(raw))
		userMsg := fmt.Sprintf("File: %s\n\n%s", c.rel, numbered)
		opts.Logf("sast-local: %s\n", c.rel)

		text, err := opts.Client.ChatJSON(ctx, model, []localllm.Message{
			{Role: "system", Content: system},
			{Role: "user", Content: userMsg},
		})
		if err != nil {
			res.Errors++
			opts.Logf("sast-local: %s — model error: %v\n", c.rel, err)
			continue
		}

		var parsed modelResponse
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			res.Malformed++
			opts.Logf("sast-local: %s — malformed JSON, dropped\n", c.rel)
			continue
		}
		res.FilesScanned++

		for _, mf := range parsed.Findings {
			if mf.Confidence < sastLocalMinConfidence {
				continue
			}
			if _, ok := sastLocalCWE[mf.Category]; !ok {
				continue // model returned a category outside our catalog
			}
			f := toFinding(c.rel, raw, mf)
			res.Findings = append(res.Findings, f)
		}
	}

	return res, nil
}

func toFinding(rel string, raw []byte, mf modelFinding) Finding {
	ls := clampLine(mf.LineStart, raw)
	le := clampLine(mf.LineEnd, raw)
	if le < ls {
		le = ls
	}
	severity := normalizeSeverity(mf.Severity)
	title := strings.TrimSpace(mf.Title)
	if title == "" {
		title = mf.Category
	}
	explanation := strings.TrimSpace(mf.Explanation)
	if explanation == "" {
		explanation = "Flagged by the local-LLM SAST pass."
	}
	// Stable content-hash so re-scans dedupe the same finding. Line-
	// independent on purpose — same finding identity as it migrates lines.
	h := sha256.Sum256([]byte(rel + "\x1F" + mf.Category + "\x1F" + title))
	return Finding{
		FilePath:    rel,
		LineStart:   ls,
		LineEnd:     le,
		Category:    mf.Category,
		Severity:    severity,
		Title:       title,
		Explanation: explanation,
		ContentHash: hex.EncodeToString(h[:16]),
		Detection:   "local-llm",
		CWE:         sastLocalCWE[mf.Category],
		OWASP:       sastLocalOWASP[mf.Category],
	}
}

func clampLine(n int, raw []byte) int {
	if n < 1 {
		return 1
	}
	// 1-based; cap at the file's actual line count so we never claim a line
	// the file doesn't have.
	lineCount := 1
	for _, b := range raw {
		if b == '\n' {
			lineCount++
		}
	}
	if n > lineCount {
		return lineCount
	}
	return n
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

func numberLines(source string) string {
	lines := strings.Split(source, "\n")
	// Right-pad width based on line count so the prefix column aligns.
	width := len(fmt.Sprintf("%d", len(lines)))
	var b strings.Builder
	for i, line := range lines {
		b.WriteString(fmt.Sprintf("%*d| %s", width, i+1, line))
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
