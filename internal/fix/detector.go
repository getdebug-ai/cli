// Local detector — regex pass over the workdir that surfaces the
// pattern shapes the deterministic patchers can fix. No LLM call, no
// network — the AI-free half of `getdebug fix --local-only`.
//
// Coverage philosophy: only patterns where the regex is high-signal
// AND the corresponding patcher is confident on a single-line shape
// land here. Categories whose detection legitimately needs semantic
// context (open-redirect, unbounded-stream, client-side-llm-key) or
// out-of-process tooling (dependency-cve → pip-audit / npm audit) are
// intentionally excluded — they CAN be fixed via the patcher, but only
// when a finding from a richer source (analyze --local-llm, hosted
// scan) supplies the line. Wiring that supply path is follow-up.
//
// In scope for v1:
//   - weak-crypto        (createHash/createHmac, hashlib.md5/sha1/new)
//   - insecure-random    (Math.random())
//   - xss                (.innerHTML = simple assignment, not == or +=)
//   - insecure-cors      ({ "Access-Control-Allow-Origin": "*" })

package fix

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Detected is one fixable-pattern hit. Mirrors the relevant subset of
// scan.Finding so the engine can drive patchers without depending on
// the SAST package.
type Detected struct {
	Category    string
	FilePath    string
	LineStart   int
	LineEnd     int
	MatchedSpan string
}

// detectorRules maps a category to its detection regex. Each rule is
// applied to every eligible source line; a match becomes a Detected
// entry. Lookup keeps category → patcher symmetry — every category
// with a detector here MUST also resolve via Lookup(category) so the
// engine can pair them.
var detectorRules = []struct {
	Category string
	// Pattern is matched against EVERY line of source for files passing
	// languageEligible. Compile-time, no per-line allocation.
	Pattern *regexp.Regexp
	// Languages is the set of file extensions this rule fires on. Empty
	// = every supported extension.
	Languages map[string]struct{}
}{
	{
		Category: "weak-crypto",
		// JS createHash/createHmac with quoted md5|sha1, OR Python
		// hashlib.md5/sha1(/.new("md5"|"sha1"). One alternation per
		// language so per-language false positives don't bleed.
		Pattern:   regexp.MustCompile(`\b(?:createHash|createHmac)\s*\(\s*["']\s*(?:md5|sha1)\s*["']|\bhashlib\.(?:md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*["'](?:md5|sha1)["']`),
		Languages: jsAndPy,
	},
	{
		Category:  "insecure-random",
		Pattern:   regexp.MustCompile(`\bMath\.random\s*\(\s*\)`),
		Languages: jsOnly,
	},
	{
		Category: "xss",
		// `.innerHTML = X` (simple assignment), not `==`, not `+=`.
		// Same shape jsInnerHTMLAssignRe uses in xss.go.
		Pattern:   regexp.MustCompile(`\.innerHTML\s*=[^=]`),
		Languages: jsOnly,
	},
	{
		Category: "insecure-cors",
		// Quoted key + : or , + quoted "*". Same shape as
		// jsCorsWildcardRe; we don't enforce backreference symmetry at
		// detection time because the patcher will. False positives
		// here just become declined patches downstream — never silent
		// rewrites.
		Pattern:   regexp.MustCompile(`["']Access-Control-Allow-Origin["']\s*[,:]\s*["']\*["']`),
		Languages: jsOnly,
	},
}

var (
	jsOnly = map[string]struct{}{
		".ts": {}, ".tsx": {}, ".js": {}, ".jsx": {}, ".mjs": {}, ".cjs": {},
	}
	jsAndPy = map[string]struct{}{
		".ts": {}, ".tsx": {}, ".js": {}, ".jsx": {}, ".mjs": {}, ".cjs": {}, ".py": {},
	}
	// Mirrors cli/internal/scan/secrets.go skip set, narrowed: vendor
	// trees and lockfiles never produce findings the patcher should
	// rewrite.
	skipDirs = map[string]struct{}{
		".git":         {},
		".hg":          {},
		".svn":         {},
		"node_modules": {},
		".next":        {},
		"dist":         {},
		"build":        {},
		".venv":        {},
		"venv":         {},
		"__pycache__":  {},
		// Don't ever recurse into a backup we created.
		// More specific markers (e.g. ".getdebug-backup-...") need a
		// prefix check, done in the walker.
	}
	// Cap per file so a generated megabyte doesn't pin the regex.
	maxFileBytes = 256 * 1024
)

// Detect walks workdir, applies each detectorRule to every eligible
// line, and returns the union of hits. Errors on individual files are
// logged via logf but never abort the walk — partial coverage is more
// useful than total failure.
func Detect(workdir string, logf func(string, ...any)) ([]Detected, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var out []Detected

	walkErr := filepath.WalkDir(workdir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logf("fix detector: walk error at %s: %v — continuing", path, err)
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if _, skip := skipDirs[name]; skip {
				return filepath.SkipDir
			}
			if strings.HasPrefix(name, ".getdebug-backup-") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == "" {
			return nil
		}
		// Each rule has its own language gate, so we don't need a
		// pre-filter here — we just open files matching ANY rule's
		// language set. Inline check keeps the rule list authoritative.
		anyApplies := false
		for _, r := range detectorRules {
			if _, ok := r.Languages[ext]; ok {
				anyApplies = true
				break
			}
		}
		if !anyApplies {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > int64(maxFileBytes) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			logf("fix detector: read %s: %v — skipping", path, err)
			return nil
		}
		rel, err := filepath.Rel(workdir, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		out = append(out, scanFile(rel, ext, string(raw))...)
		return nil
	})
	if walkErr != nil {
		return out, walkErr
	}
	return out, nil
}

// scanFile applies every applicable detector rule to source and emits
// one Detected per (rule, matching line). Multiple rules can hit the
// same line — each becomes its own finding (one per category).
func scanFile(relPath, ext, source string) []Detected {
	var out []Detected
	lines := strings.Split(source, "\n")
	for _, rule := range detectorRules {
		if _, ok := rule.Languages[ext]; !ok {
			continue
		}
		for i, line := range lines {
			loc := rule.Pattern.FindStringIndex(line)
			if loc == nil {
				continue
			}
			out = append(out, Detected{
				Category:    rule.Category,
				FilePath:    relPath,
				LineStart:   i + 1,
				LineEnd:     i + 1,
				MatchedSpan: line[loc[0]:loc[1]],
			})
		}
	}
	return out
}
