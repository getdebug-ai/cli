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
	"errors"
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
	// Optional secondary CWE/OWASP for categories whose detection covers
	// multiple top-level buckets — e.g. unsafe-tool-output is CWE-94
	// (broader code injection) AND CWE-78 (OS command injection) for the
	// subprocess subset. When set, the SARIF emitter surfaces both via
	// `external/cwe/cwe-<n>` tags so consumers (GitHub Code Scanning,
	// GitLab) index the finding under both.
	SecondaryCWE   string `json:"secondaryCwe,omitempty"`
	SecondaryOWASP string `json:"secondaryOwasp,omitempty"`
	// Verification is populated by VerifyFindings (called from analyze.go
	// when --verify is on). Always nil before the verification pass runs,
	// and nil for non-secret findings. Pointer-shape so the absence of a
	// verification record is distinguishable from a "no verifier"
	// unknown — the JSON / SARIF output should omit the field in the
	// first case but emit it in the second.
	Verification *Verification `json:"verification,omitempty"`
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
	// Go lockfile — full of h1: + dependency hashes that look like
	// high-entropy secrets to the regex pass. Never contains real
	// credentials; safe to skip alongside the other lockfiles.
	"go.sum": {},
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
	// Google OAuth 2.0 client secrets follow the GOCSPX-<28-char> shape.
	// Found in the wild during the 2026-05-31 bench sweep
	// (ArtemXTech/claude-code-obsidian-starter shipped one bundled into
	// a plugin's main.js).
	{"Google OAuth client secret", regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_\-]{28}\b`)},
	// HuggingFace user access tokens (`hf_<34+ alphanumeric>`). Bench
	// sweep showed 3 hits in NJUxlj/Travel-Agent fine-tuning scripts;
	// real-looking tokens in committed code.
	{"HuggingFace token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{34,}\b`)},
	{"GitHub PAT (classic)", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`)},
	{"Stripe secret key", regexp.MustCompile(`\bsk_(live|test)_[A-Za-z0-9]{24,}\b`)},
	{"Stripe restricted key", regexp.MustCompile(`\brk_(live|test)_[A-Za-z0-9]{24,}\b`)},
	{"Paystack secret key", regexp.MustCompile(`\bsk_(live|test)_[a-f0-9]{40,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	// FIX 8 (2026-06-06): Anthropic must precede OpenAI because
	// `sk-ant-…` matches the more general OpenAI regex `\bsk-…` first
	// otherwise — every Anthropic token in the wild was misclassified
	// as OpenAI, then verifier-rejected (HTTP 401 from openai) and
	// labelled REJECTED instead of the user's actual provider. Specific
	// patterns before general ones across this table.
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{40,}\b`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b`)},
	// FIX 7 (2026-06-06): xAI / GitLab / npm. The verifiers in
	// verify.go (providersByLabel) ship for these providers, but no
	// detector regex existed — every real key from these providers
	// was simply not surfaced. Labels must match the providersByLabel
	// keys exactly so the verifier wires up.
	{"xAI API key", regexp.MustCompile(`\bxai-[A-Za-z0-9]{32,}\b`)},
	{"GitLab personal access token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`)},
	{"npm access token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |)PRIVATE KEY-----`)},
	{"SendGrid API key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`)},
	// Heroku uses a UUID shape; only flag when "heroku" sits nearby. Go's
	// RE2 engine has no lookahead — the proximity check is done in code.
	{"Heroku API key", regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)},
}

var (
	keywordNear     = regexp.MustCompile(`(?i)\b(secret|token|password|passwd|api[_-]?key|access[_-]?key|auth|credential|priv(?:ate)?[_-]?key|client[_-]?secret)\b`)
	// FIX 1 (2026-06-06 crewAI dogfood): added `fake[_-]`, `mock[_-]`,
	// `stub[_-]`. crewAI's `.env.test` uses `fake-password`, `mock_key`,
	// `stub-token` as test fixture values; 5 critical FPs came from
	// these shapes slipping through. The `[_-]` suffix keeps coverage
	// tight (matches `fake-` / `fake_` but not `faker.io`-style
	// substring hits at the start of an unrelated identifier).
	placeholder     = regexp.MustCompile(`(?i)^(your[_-]|changeme|change[_-]me|replace[_-]?me|example|sample|dummy|xxx|todo|placeholder|insert[_-]|fake[_-]|mock[_-]|stub[_-])`)
	valueCandidate  = regexp.MustCompile("[\"'`]?[A-Za-z0-9+/=_\\-\\.]{20,}[\"'`]?")
	urlPrefix       = regexp.MustCompile(`^https?://`)
	testFile        = regexp.MustCompile(`(?i)\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs|py)$`)
	testDir         = regexp.MustCompile(`(?i)(^|/)(__tests__|__mocks__|tests?|specs?|fixtures?)/`)
	markdownExt     = regexp.MustCompile(`(?i)\.(md|mdx)$`)
	// envTemplate matches files that exist explicitly to document required
	// env vars with placeholder values: `.env.example`, `.env.sample`,
	// `.env.template`, `.env.dist`, `.env.tpl`, and the suffix variants
	// (`.env.local.example`, `.env.prod.template`, etc.). These files are
	// skipped from BOTH the regex pass and the entropy pass — they're
	// docs by convention. Supersedes the older `envExample` + `envSample`
	// pair which only suppressed entropy.
	envTemplate     = regexp.MustCompile(`(?i)(^|/)\.env(\.[^/]+)?\.(example|sample|template|dist|tpl)$`)
	// docFile matches files where regex hits for "Private key block" and
	// similar PEM-shaped patterns are almost certainly documentation
	// examples, not committed credentials. CHANGELOG/SNAPSHOT/README/.md
	// are the routine offenders. Used by docSuppressedPatterns below.
	docFile         = regexp.MustCompile(`(?i)(\.(md|mdx|rst|txt|adoc)$|(^|/)(CHANGELOG|HISTORY|SNAPSHOT|README|NOTES)(\..+)?$)`)
	// envVarRead matches references to env-var accessors. The value the
	// detector picks up (e.g. `import.meta.env.VITE_AUTH_PASSWORD`) is
	// the name of an env var being read, not the secret itself. Skip
	// in entropy pass — the actual secret, if any, lives at the env-var
	// definition, which lives in a `.env` file the regex pass already covers.
	envVarRead      = regexp.MustCompile(`(?i)(process\.env|import\.meta\.env|os\.environ|os\.getenv|System\.getenv)`)
	herokuContextRe = regexp.MustCompile(`(?i)heroku`)
)

// docSuppressedPatterns names patterns whose regex hits in doc files
// (per docFile above) are FP-shaped. Adding here is a tighter trade than
// dropping the pattern entirely: regular code paths still flag, only
// documentation matches are suppressed.
//
// `HuggingFace token` joined the set 2026-06-06 — getdebug's own
// METHODOLOGY.md labels real-world tokens it found in other people's
// public repos (so it can score detector recall against them), and
// those literal hf_… strings tripped the regex inside the markdown
// explanation paragraph. Routine offender, same shape as PEM in markdown.
var docSuppressedPatterns = map[string]struct{}{
	"Private key block": {},
	"HuggingFace token": {},
}

// entropyScanEnabled mirrors the TS predicate of the same name. Pass 1
// (regex) runs on every file BY DEFAULT but is also skipped for env
// templates via secretScanEligible below (otherwise placeholder values
// in `.env.template` files generate critical-severity FPs). Pass 2
// (entropy) is additionally suppressed for tests, markdown, and env
// templates where high-entropy strings are routine.
func entropyScanEnabled(relPath string) bool {
	rel := filepath.ToSlash(relPath)
	switch {
	case testFile.MatchString(rel),
		testDir.MatchString(rel),
		markdownExt.MatchString(rel),
		envTemplate.MatchString(rel):
		return false
	}
	return true
}

// secretScanEligible returns false for files that are documented placeholder
// territory and should be skipped by BOTH the regex and entropy passes.
// Today this is just env templates (`.env.example`, `.env.template`, ...).
// Other detectors (test fixtures, markdown) remain eligible for the regex
// pass because real secrets in those locations are still secrets — but
// .env.<placeholder-suffix> files are explicitly docs by convention.
func secretScanEligible(relPath string) bool {
	rel := filepath.ToSlash(relPath)
	return !envTemplate.MatchString(rel)
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
	// IgnoreRules applies .gitignore + .getdebug-ignore patterns.
	// Nil means "no additional rules" — only the built-in skipDirs +
	// the per-path Ignore set above are honored. Loaded by
	// LoadIgnoreRules at the analyze command level.
	IgnoreRules *IgnoreRuleset
}

// Result is what ScanSecrets returns.
type Result struct {
	Findings     []Finding
	ScannedFiles int
	ScannedBytes int64
	Truncated    bool // hit MAX_TOTAL_BYTES before finishing the walk
	// TruncatedAt is the (rel-to-Workdir) path of the file whose size
	// would have pushed the run over the byte budget. The CLI surfaces
	// it so the user has an actionable anchor for `.getdebug-ignore`
	// rather than the opaque "hit 20 MB cap" message. Empty when
	// !Truncated.
	TruncatedAt string
}

// ScanSecrets runs the two-pass secret detector across Workdir.
// Manually recurses with os.ReadDir per directory (rather than
// filepath.WalkDir) because we need the full directory listing in hand
// to check the database-data-dir sentinels (PG_VERSION etc.) before
// descending — WalkDir delivers entries individually.
func ScanSecrets(opts ScanOptions) (*Result, error) {
	res := &Result{}
	seen := make(map[string]struct{})
	// walkDir returns filepath.SkipAll when the cumulative byte budget
	// is hit — that's Go's idiomatic "stop walking, we're done"
	// sentinel, NOT a failure. Treat it as a clean truncation: the
	// caller still gets every finding collected so far, with
	// res.Truncated already set. Any other error is a real failure.
	if err := walkDir(opts.Workdir, opts.Workdir, opts.Ignore, opts.IgnoreRules, seen, res); err != nil && !errors.Is(err, filepath.SkipAll) {
		return res, err
	}
	return res, nil
}

// walkDir returns filepath.SkipAll when the cumulative byte budget is hit.
// Other errors are non-fatal: directories that can't be read are skipped,
// matching the TS implementation's posture.
func walkDir(root, dir string, ignore map[string]struct{}, rules *IgnoreRuleset, seen map[string]struct{}, res *Result) error {
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
			// .gitignore + .getdebug-ignore directory check. If the dir
			// itself is ignored we skip the whole subtree without ever
			// reading its contents — same shape skipDirs uses.
			if rules != nil {
				relDir, relErr := filepath.Rel(root, abs)
				if relErr == nil && rules.IsDirIgnored(filepath.ToSlash(relDir)) {
					continue
				}
			}
			if err := walkDir(root, abs, ignore, rules, seen, res); err != nil {
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
		if rules != nil && rules.IsIgnored(rel) {
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
			res.TruncatedAt = rel
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
	// Files that exist explicitly to document env-var shapes (`.env.template`,
	// `.env.example`, etc.) are skipped wholesale — both regex and entropy
	// passes. They're placeholder territory by convention; flagging
	// `sk-your-key-here` as critical is noise.
	if !secretScanEligible(rel) {
		return
	}
	runEntropy := entropyScanEnabled(rel)
	inDoc := docFile.MatchString(rel)
	lines := splitLines(content)
	// FIX 2 (2026-06-06): for Python source files, pre-compute the set
	// of lines inside `"""…"""` / `'''…'''` docstrings so the
	// `Private key block` regex doesn't fire on PEM-shaped example
	// values inside docstrings or doctest lines. The bench/realworld
	// crewAI-getdebug fixture and several stdlib `ssl` / `cryptography`
	// docstrings tripped this before. Narrow scope — non-PEM regex
	// matches still fire normally in docstrings (a real `sk-…` in a
	// docstring is still a leak).
	var pyDocstring map[int]bool
	isPython := strings.HasSuffix(strings.ToLower(rel), ".py")
	if isPython {
		pyDocstring = pythonDocstringLines(content)
	}
	for i, line := range lines {
		if line == "" {
			continue
		}
		lineNo := i + 1

		// Pass 1: provider regex.
		//
		// FIX 8 (2026-06-06): patterns earlier in the table are MORE
		// specific (Anthropic `sk-ant-…` precedes OpenAI `sk-…`). Track
		// the character ranges already consumed on this line and skip
		// any later-pattern match that overlaps a consumed range. Order
		// alone didn't help because the loop walks every pattern and
		// emits one finding per match — without occupancy tracking,
		// `sk-ant-DDDD…` produced both an Anthropic AND an OpenAI
		// finding, then the verifier rejected the OpenAI variant with
		// HTTP 401 and the user thought their Anthropic key was burned.
		consumed := make([]bool, len(line))
		overlapsConsumed := func(m []int) bool {
			for i := m[0]; i < m[1] && i < len(consumed); i++ {
				if consumed[i] {
					return true
				}
			}
			return false
		}
		markConsumed := func(m []int) {
			for i := m[0]; i < m[1] && i < len(consumed); i++ {
				consumed[i] = true
			}
		}
		for _, pat := range regexPatterns {
			// Heroku UUID is over-broad alone; require "heroku" on the line.
			if pat.label == "Heroku API key" && !herokuContextRe.MatchString(line) {
				continue
			}
			// FP-shaped patterns (e.g. "Private key block") in docs/CHANGELOGs
			// are documentation, not credentials. Suppress for the
			// well-known offenders rather than dropping the pattern globally.
			if inDoc {
				if _, suppress := docSuppressedPatterns[pat.label]; suppress {
					continue
				}
			}
			// FIX 2: PEM-block markers inside Python docstrings or
			// doctest lines (`>>> ...`, `... continuation`) are
			// documentation examples. Narrow scope — only the
			// `Private key block` pattern is suppressed, so a real
			// `sk-…` accidentally pasted into a docstring still fires.
			if isPython && pat.label == "Private key block" {
				if pyDocstring[lineNo] || isPythonDoctestLine(line) {
					continue
				}
			}
			matches := pat.re.FindAllStringIndex(line, -1)
			for _, m := range matches {
				if overlapsConsumed(m) {
					continue
				}
				matched := trimMatch(line[m[0]:m[1]])
				hash := hashFinding(rel, strconv.Itoa(lineNo), "secrets", "regex", pat.label, matched)
				if _, dup := seen[hash]; dup {
					continue
				}
				seen[hash] = struct{}{}
				markConsumed(m)
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
			// `import.meta.env.VITE_AUTH_PASSWORD`, `process.env.STRIPE_KEY`,
			// `os.environ["DB_URL"]` etc. are env-var NAME reads, not values.
			// The actual secret (if any) lives at the env-var DEFINITION
			// in a `.env*` file, which the regex pass handles. Without this
			// guard the env-var read trips entropy because the variable name
			// is long + uppercase + sits next to a "password"/"key"/"token"
			// keyword on the same line.
			if envVarRead.MatchString(stripped) {
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
