// Package scan implements the local detectors that ship with the CLI.
//
// Right now: a port of workers/src/security/secrets.ts. Two-pass — provider
// regex (high confidence) + keyword-proximity + Shannon entropy fallback —
// kept independent from the server-side TS so `npx getdebug analyze . --ci`
// works offline with no account.
//
// Behavioral parity with the TS implementation is enforced by
// secrets_test.go. When updating either, update both.
package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Severity levels. Mirrors api/src/db/schema.ts severityEnum.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is the CLI-local shape of a security finding. Maps onto the
// SecurityFinding type in workers/src/security/types.ts.
type Finding struct {
	FilePath    string `json:"filePath"`
	LineStart   int    `json:"lineStart"`
	LineEnd     int    `json:"lineEnd"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Explanation string `json:"explanation"`
	ContentHash string `json:"contentHash"`
	Pattern     string `json:"pattern,omitempty"`
	Detection   string `json:"detection,omitempty"` // "regex" | "entropy"
	Snippet     string `json:"snippet,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	OWASP       string `json:"owasp,omitempty"`
}

// Mirrors workers/src/security/secrets.ts SKIP_DIRS.
var skipDirs = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {},
	"node_modules":     {},
	".next":            {},
	".nuxt":            {},
	"dist":             {},
	"build":            {},
	"out":              {},
	".turbo":           {},
	".cache":           {},
	"coverage":         {},
	"__pycache__":      {},
	".venv":            {},
	"venv":             {},
	".tox":             {},
	".mypy_cache":      {},
	".pytest_cache":    {},
	"vendor":           {},
	"third_party":      {},
	"bower_components": {},
}

var generatedExts = map[string]struct{}{
	".tsbuildinfo": {},
	".map":         {},
	".snap":        {},
	".lock":        {},
	".lockb":       {},
}

var generatedBasenames = map[string]struct{}{
	"package-lock.json": {}, "pnpm-lock.yaml": {}, "yarn.lock": {},
	"poetry.lock": {}, "uv.lock": {}, "Pipfile.lock": {},
	"Gemfile.lock": {}, "composer.lock": {}, "Cargo.lock": {},
	"bun.lockb": {}, ".eslintcache": {}, ".stylelintcache": {},
}

var binaryExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {},
	".bmp": {}, ".ico": {}, ".svg": {}, ".pdf": {}, ".zip": {},
	".gz": {}, ".tar": {}, ".tgz": {}, ".bz2": {}, ".7z": {}, ".rar": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	".mp3": {}, ".mp4": {}, ".mov": {}, ".webm": {}, ".wav": {}, ".ogg": {},
	".so": {}, ".dll": {}, ".dylib": {}, ".class": {}, ".jar": {}, ".wasm": {}, ".node": {},
}

const (
	maxFileBytes     = 512 * 1024
	maxTotalBytes    = 20 * 1024 * 1024
	maxMatchPreview  = 80
	entropyThreshold = 4.5
	entropyMinLen    = 20
)

// regexPattern is one entry in the provider-regex table.
type regexPattern struct {
	label string
	re    *regexp.Regexp
}

// Provider regex set. MUST stay in sync with REGEX_PATTERNS in
// workers/src/security/secrets.ts.
var regexPatterns = []regexPattern{
	{"AWS access key", regexp.MustCompile(`\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"GitHub PAT (classic)", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`)},
	{"Stripe secret key", regexp.MustCompile(`\bsk_(live|test)_[A-Za-z0-9]{24,}\b`)},
	{"Stripe restricted key", regexp.MustCompile(`\brk_(live|test)_[A-Za-z0-9]{24,}\b`)},
	{"Paystack secret key", regexp.MustCompile(`\bsk_(live|test)_[a-f0-9]{40,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b`)},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{40,}\b`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |)PRIVATE KEY-----`)},
	{"SendGrid API key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`)},
	// Heroku uses a UUID shape; only flag when "heroku" sits nearby. Go's
	// RE2 engine has no lookahead — the proximity check is done in code.
	{"Heroku API key", regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)},
}

var (
	keywordNear     = regexp.MustCompile(`(?i)\b(secret|token|password|passwd|api[_-]?key|access[_-]?key|auth|credential|priv(?:ate)?[_-]?key|client[_-]?secret)\b`)
	placeholder     = regexp.MustCompile(`(?i)^(your[_-]|changeme|change[_-]me|replace[_-]?me|example|sample|dummy|xxx|todo|placeholder|insert[_-])`)
	valueCandidate  = regexp.MustCompile("[\"'`]?[A-Za-z0-9+/=_\\-\\.]{20,}[\"'`]?")
	urlPrefix       = regexp.MustCompile(`^https?://`)
	testFile        = regexp.MustCompile(`(?i)\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs|py)$`)
	testDir         = regexp.MustCompile(`(?i)(^|/)(__tests__|__mocks__|tests?|specs?|fixtures?)/`)
	markdownExt     = regexp.MustCompile(`(?i)\.(md|mdx)$`)
	envExample      = regexp.MustCompile(`(?i)(^|/)\.env(\.[^/]+)?\.example$`)
	envSample       = regexp.MustCompile(`(?i)(^|/)\.env\.sample$`)
	herokuContextRe = regexp.MustCompile(`(?i)heroku`)
)

// entropyScanEnabled mirrors the TS predicate of the same name. Pass 1
// (regex) runs on every file; Pass 2 (entropy) is suppressed for tests,
// docs, and env templates where high-entropy strings are routine.
func entropyScanEnabled(relPath string) bool {
	rel := filepath.ToSlash(relPath)
	switch {
	case testFile.MatchString(rel),
		testDir.MatchString(rel),
		markdownExt.MatchString(rel),
		envExample.MatchString(rel),
		envSample.MatchString(rel):
		return false
	}
	return true
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	// secret-candidate strings are restricted to ASCII alphanum + +/=._-
	// (see valueCandidate), so a byte-frequency table is faithful and
	// avoids the map allocation per call.
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func hashFinding(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0x1f}) // unit separator, matches the TS "␟" delimiter byte-wise
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func trimMatch(v string) string {
	if len(v) <= maxMatchPreview {
		return v
	}
	return v[:maxMatchPreview] + "…"
}

// isBinarySample mirrors the TS heuristic: a NUL byte in the first 8 KB
// means binary. Real text files virtually never embed NUL.
func isBinarySample(buf []byte) bool {
	head := buf
	if len(head) > 8192 {
		head = head[:8192]
	}
	return bytes.IndexByte(head, 0) != -1
}

// ScanOptions controls the secrets walk.
type ScanOptions struct {
	// Workdir is the root to walk. Required.
	Workdir string
	// Ignore is a set of relative paths to skip (forward-slash form).
	Ignore map[string]struct{}
}

// Result is what ScanSecrets returns.
type Result struct {
	Findings     []Finding
	ScannedFiles int
	ScannedBytes int64
	Truncated    bool // hit MAX_TOTAL_BYTES before finishing the walk
}

// ScanSecrets runs the two-pass secret detector across Workdir.
// Manually recurses with os.ReadDir per directory (rather than
// filepath.WalkDir) because we need the full directory listing in hand
// to check the database-data-dir sentinels (PG_VERSION etc.) before
// descending — WalkDir delivers entries individually.
func ScanSecrets(opts ScanOptions) (*Result, error) {
	res := &Result{}
	seen := make(map[string]struct{})
	if err := walkDir(opts.Workdir, opts.Workdir, opts.Ignore, seen, res); err != nil {
		return res, err
	}
	return res, nil
}

// walkDir returns filepath.SkipAll when the cumulative byte budget is hit.
// Other errors are non-fatal: directories that can't be read are skipped,
// matching the TS implementation's posture.
func walkDir(root, dir string, ignore map[string]struct{}, seen map[string]struct{}, res *Result) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // unreadable dir: skip, don't fail the whole scan
	}

	// Database data-dir sentinels: skip the whole subtree.
	for _, e := range entries {
		n := e.Name()
		if n == "PG_VERSION" || n == "ibdata1" || n == "mongod.lock" {
			return nil
		}
	}

	for _, entry := range entries {
		name := entry.Name()
		abs := filepath.Join(dir, name)

		if entry.IsDir() {
			if _, skip := skipDirs[name]; skip {
				continue
			}
			if err := walkDir(root, abs, ignore, seen, res); err != nil {
				return err
			}
			continue
		}
		if !entry.Type().IsRegular() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(name))
		if _, b := binaryExts[ext]; b {
			continue
		}
		if _, g := generatedExts[ext]; g {
			continue
		}
		if _, g := generatedBasenames[name]; g {
			continue
		}

		rel, relErr := filepath.Rel(root, abs)
		if relErr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if _, skip := ignore[rel]; skip {
			continue
		}

		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		size := info.Size()
		if size == 0 || size > maxFileBytes {
			continue
		}
		if res.ScannedBytes+size > maxTotalBytes {
			res.Truncated = true
			return filepath.SkipAll
		}

		content, readErr := os.ReadFile(abs)
		if readErr != nil {
			continue
		}
		if isBinarySample(content) {
			continue
		}
		res.ScannedBytes += size
		res.ScannedFiles++

		scanContent(content, rel, seen, &res.Findings)
	}
	return nil
}

func scanContent(content []byte, rel string, seen map[string]struct{}, out *[]Finding) {
	runEntropy := entropyScanEnabled(rel)
	lines := splitLines(content)
	for i, line := range lines {
		if line == "" {
			continue
		}
		lineNo := i + 1

		// Pass 1: provider regex.
		for _, pat := range regexPatterns {
			// Heroku UUID is over-broad alone; require "heroku" on the line.
			if pat.label == "Heroku API key" && !herokuContextRe.MatchString(line) {
				continue
			}
			matches := pat.re.FindAllStringIndex(line, -1)
			for _, m := range matches {
				matched := trimMatch(line[m[0]:m[1]])
				hash := hashFinding(rel, strconv.Itoa(lineNo), "secrets", "regex", pat.label, matched)
				if _, dup := seen[hash]; dup {
					continue
				}
				seen[hash] = struct{}{}
				*out = append(*out, Finding{
					FilePath:    rel,
					LineStart:   lineNo,
					LineEnd:     lineNo,
					Category:    "secrets",
					Severity:    SeverityCritical,
					Title:       pat.label + " detected",
					Explanation: fmt.Sprintf("A value matching the %s format was found at %s:%d. Treat the credential as burned — rotate it immediately, then scrub it from git history (BFG or git-filter-repo) and force-push. getdebug never auto-fixes secrets: removing the line locally is not enough.", pat.label, rel, lineNo),
					ContentHash: hash,
					Detection:   "regex",
					Pattern:     pat.label,
					Snippet:     matched,
					CWE:         "CWE-798",
					OWASP:       "A07:2021",
				})
			}
		}

		// Pass 2: keyword-proximity + Shannon entropy.
		if !runEntropy {
			continue
		}
		if !keywordNear.MatchString(line) {
			continue
		}
		for _, m := range valueCandidate.FindAllStringIndex(line, -1) {
			raw := line[m[0]:m[1]]
			stripped := strings.Trim(raw, "\"'`")
			if len(stripped) < entropyMinLen {
				continue
			}
			if placeholder.MatchString(stripped) {
				continue
			}
			if urlPrefix.MatchString(stripped) {
				continue
			}
			h := shannonEntropy(stripped)
			if h < entropyThreshold {
				continue
			}
			matched := trimMatch(stripped)
			hash := hashFinding(rel, strconv.Itoa(lineNo), "secrets", "entropy", matched)
			if _, dup := seen[hash]; dup {
				continue
			}
			seen[hash] = struct{}{}
			kw := keywordNear.FindString(line)
			if kw == "" {
				kw = "credential"
			}
			*out = append(*out, Finding{
				FilePath:    rel,
				LineStart:   lineNo,
				LineEnd:     lineNo,
				Category:    "secrets",
				Severity:    SeverityCritical,
				Title:       "High-entropy string near credential keyword",
				Explanation: fmt.Sprintf("Entropy %.2f bits/char near %q. The matched value is long and random enough to be a real secret. If this is intentional (e.g. a public key, an example value), commit a comment explaining it; otherwise rotate and scrub history.", h, kw),
				ContentHash: hash,
				Detection:   "entropy",
				Snippet:     matched,
				CWE:         "CWE-798",
				OWASP:       "A07:2021",
			})
		}
	}
}

// splitLines is allocation-conscious because it runs once per scanned file.
// strings.Split would over-allocate; bufio.Scanner has line-length limits we
// don't want; this strips trailing CR and returns the slice in one pass.
func splitLines(b []byte) []string {
	out := make([]string, 0, bytes.Count(b, []byte{'\n'})+1)
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			end := i
			if end > start && b[end-1] == '\r' {
				end--
			}
			out = append(out, string(b[start:end]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
