// Ignore rules — .gitignore + .getdebug-ignore parsing.
//
// Two layers, each gitignore-syntax (including negation with `!`):
//
//   1. .gitignore at the workdir root — respected by default so the
//      CLI matches what the hosted scan sees (the hosted side clones
//      from GitHub, which only ships tracked files). Disable with
//      --no-gitignore on the analyze command.
//
//   2. .getdebug-ignore at the workdir root — scanner-specific config
//      that ALWAYS applies, regardless of --no-gitignore. Used for
//      "scan this even though it's gitignored" (with !pattern) or
//      "skip this tracked file" (e.g. **/*.test.ts in a TS repo).
//
// Both files are optional; missing means "no rules from this layer."
// Order: a path is ignored if either layer matches it AND the active
// layer's matcher returns true. .getdebug-ignore negations override
// .gitignore exclusions.
//
// Nested .gitignore files (deeper in the tree) are NOT honored today —
// most repos place their rules at the root and a single-file parser
// covers 95% of real cases. Re-evaluate if users hit the edge case.

package scan

import (
	"os"
	"path/filepath"
	"strings"

	ignore "github.com/sabhiram/go-gitignore"
)

// IgnoreRuleset holds the parsed ignore matchers for a scan workdir.
// Zero value is safe to use: every IsIgnored call returns false.
//
// Nested .gitignore files are honored: each .gitignore found during a
// pre-walk gets its own matcher scoped to the directory the file lives
// in. A path is checked against every matcher whose scope is an
// ancestor of the path (workdir-relative). This matches git's
// semantics for nested .gitignore files like `bench/.gitignore`
// excluding `results/`.
type IgnoreRuleset struct {
	// gitignores is the ordered list of (scope-dir, matcher) pairs
	// from .gitignore files found anywhere under workdir. The
	// workdir's own .gitignore has scopeDir="". Empty list when
	// --no-gitignore is on or no .gitignore files exist.
	gitignores []scopedMatcher
	// .getdebug-ignore matcher at the workdir root. Always applied.
	custom *ignore.GitIgnore
	// Built-in default patterns (test files, fixtures, snapshots).
	// Compiled from BuiltInIgnorePatterns and applied unless
	// --no-default-ignores. Nil when the caller passes
	// respectDefaults=false.
	defaults *ignore.GitIgnore
}

// BuiltInIgnorePatterns returns the conservative default exclusions
// every scan applies unless the user passes --no-default-ignores.
// Three groups, all UNAMBIGUOUS so defaults never silently drop real
// source code:
//
//  1. Test scaffolding — unit-test files and reserved test directories.
//  2. Local-dev env overrides — `.env.local`, `.env.<env>.local` — the
//     framework-wide convention for gitignored per-dev secrets. The
//     committed `.env` / `.env.production` shapes are NOT skipped: a
//     real key in them is a real leak, and the scanner keeps catching
//     it. Templates (`.env.example` etc.) are re-included by the
//     secret-pass's own eligibility check.
//  3. Scanner output / bundled fixture data — JSON files the bench
//     harness writes that contain the secret patterns it found in
//     fixtures, creating a recursive feedback loop on re-scan; and the
//     fixture data the web app ships for the `/bench` page.
//
// Deliberately NOT included (too ambiguous):
//   - fixtures/, bench/, examples/ — common legitimate directory
//     names in user code (only the scoped scanner-output JSONs under
//     them are skipped; the source code is still scanned)
//   - **/__init__.py, conftest.py — Python markers that could be
//     legit
//
// The user can always override with a `!` line in .getdebug-ignore.
func BuiltInIgnorePatterns() []string {
	return []string{
		// ── Group 1: test scaffolding ────────────────────────────
		// JS/TS test files
		"**/*.test.ts",
		"**/*.test.tsx",
		"**/*.test.js",
		"**/*.test.jsx",
		"**/*.test.mjs",
		"**/*.test.cjs",
		"**/*.spec.ts",
		"**/*.spec.tsx",
		"**/*.spec.js",
		"**/*.spec.jsx",
		"**/*.spec.mjs",
		"**/*.spec.cjs",
		// Go test files (toolchain convention)
		"**/*_test.go",
		// Python test files (pytest convention)
		"**/test_*.py",
		"**/*_test.py",
		// Jest's reserved double-underscore directories
		"**/__tests__/**",
		"**/__fixtures__/**",
		"**/__snapshots__/**",
		"**/__mocks__/**",
		// Go's testdata convention (go build ignores it too)
		"**/testdata/**",

		// ── Group 2: local-dev env overrides ─────────────────────
		// `.env.local` and `.env.<env>.local` are the framework-wide
		// convention (Next.js, Vite, Vue, CRA, Astro all ship the same
		// gitignore line) for "gitignored, per-developer local secrets."
		// When they're in a scan workdir it's the dev's own secrets,
		// not a committed leak. NOTE: `.env` / `.env.production` /
		// `.env.development` etc. are NOT in this group — they're the
		// shapes a careless commit would expose, so the scanner keeps
		// flagging them. Templates (`.env.example` etc.) are already
		// handled by the secret-pass's eligibility check.
		"**/.env.local",
		"**/.env.*.local",

		// ── Group 3: scanner output + bundled fixture data ───────
		// Bench harness output: each run writes a JSON file containing
		// every secret pattern it found in the fixtures. The next scan
		// finds them all again. Recursive feedback loop.
		"**/bench/results/**",
		"**/bench-results/**",
		"**/benchmarks/results/**",
		// Single-file fixture corpora bundled into the web app for
		// display on the `/bench` page (or equivalent). Common shape:
		// `bench-fixtures.json`, `<name>-bench-fixtures.json`.
		"**/bench-fixtures.json",
		"**/*-bench-fixtures.json",
		// Coverage tool output — high-entropy file hashes, never holds
		// real credentials. node_modules-shape skip pattern.
		"**/coverage/**",
		"**/.nyc_output/**",
		// Tool audit logs / sidecar state — gstack browse audit, the
		// vulnhuntr checkpoint dir, etc. Machine output, not source.
		"**/.gstack/**",
		"**/.vulnhuntr_checkpoint/**",
	}
}

// scopedMatcher pairs a .gitignore file's matcher with the directory
// the file was found in (relative to the workdir, forward-slash form,
// empty string for the workdir itself). A path is checked against the
// matcher only when the path is under scopeDir.
type scopedMatcher struct {
	scopeDir string
	matcher  *ignore.GitIgnore
}

// LoadIgnoreRules reads every .gitignore under workdir + a single
// .getdebug-ignore at the workdir root, plus the built-in default
// patterns when respectDefaults=true.
//
// respectGitignore=false skips the .gitignore traversal entirely
// (the --no-gitignore code path). respectDefaults=false skips the
// built-in test-scaffolding exclusions (the --no-default-ignores
// code path). .getdebug-ignore always applies regardless of either
// flag — it's the user's scanner-specific config.
//
// The traversal honors `skipDirs` (no descending into node_modules,
// .next, etc.) so we don't pay the cost of reading thousands of
// vendored .gitignores. Errors are non-fatal: a malformed file is
// reported via logf and the scan continues with no rules from that
// file. Honest degradation.
func LoadIgnoreRules(workdir string, respectGitignore, respectDefaults bool, logf func(format string, args ...any)) *IgnoreRuleset {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	rs := &IgnoreRuleset{}
	if respectDefaults {
		// CompileIgnoreLines never fails on syntactically-valid
		// patterns, but defend defensively in case a future hand-edit
		// breaks the list.
		defaults := ignore.CompileIgnoreLines(BuiltInIgnorePatterns()...)
		rs.defaults = defaults
	}
	if respectGitignore {
		// Walk for .gitignore files. We keep the walk tight by skipping
		// the same dirs the scan walkers do — no point loading
		// node_modules/.gitignore.
		_ = filepath.WalkDir(workdir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				if _, skip := skipDirs[d.Name()]; skip {
					return filepath.SkipDir
				}
				if strings.HasPrefix(d.Name(), ".getdebug-backup-") {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() != ".gitignore" {
				return nil
			}
			gi, err := loadIgnoreFile(path)
			if err != nil {
				logf("ignore: read %s: %v — continuing without it", path, err)
				return nil
			}
			if gi == nil {
				return nil
			}
			dir := filepath.Dir(path)
			rel, _ := filepath.Rel(workdir, dir)
			scope := filepath.ToSlash(rel)
			if scope == "." {
				scope = ""
			}
			rs.gitignores = append(rs.gitignores, scopedMatcher{scopeDir: scope, matcher: gi})
			return nil
		})
	}
	gd, err := loadIgnoreFile(filepath.Join(workdir, ".getdebug-ignore"))
	if err != nil {
		logf("ignore: read .getdebug-ignore: %v — continuing without it", err)
	} else if gd != nil {
		rs.custom = gd
	}
	return rs
}

// loadIgnoreFile returns nil, nil when the file doesn't exist (the
// common case). Non-nil error only on truly unexpected I/O issues so
// the caller can decide whether to surface them.
func loadIgnoreFile(path string) (*ignore.GitIgnore, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	gi, err := ignore.CompileIgnoreFile(path)
	if err != nil {
		return nil, err
	}
	return gi, nil
}

// IsIgnored returns true when relPath matches either layer's rules.
// `relPath` must be relative to the workdir LoadIgnoreRules was called
// with, using forward slashes (filepath.ToSlash).
//
// Empty path returns false — the workdir itself is never ignored.
func (r *IgnoreRuleset) IsIgnored(relPath string) bool {
	if r == nil || relPath == "" || relPath == "." {
		return false
	}
	rel := filepath.ToSlash(relPath)
	if r.custom != nil && r.custom.MatchesPath(rel) {
		return true
	}
	if r.defaults != nil && r.defaults.MatchesPath(rel) {
		return true
	}
	for _, sm := range r.gitignores {
		sub, ok := relativeTo(sm.scopeDir, rel)
		if !ok {
			continue
		}
		if sm.matcher.MatchesPath(sub) {
			return true
		}
	}
	return false
}

// IsDirIgnored is the same as IsIgnored but for a directory path.
// Callers can use filepath.WalkDir's `if d.IsDir() { ... }` branch to
// skip whole subtrees. Internally we check both the bare path and the
// trailing-slash form so directory-only patterns (`foo/`) match.
func (r *IgnoreRuleset) IsDirIgnored(relDir string) bool {
	if r == nil || relDir == "" || relDir == "." {
		return false
	}
	rel := filepath.ToSlash(relDir)
	relSlash := rel
	if !strings.HasSuffix(relSlash, "/") {
		relSlash = rel + "/"
	}
	if r.custom != nil && (r.custom.MatchesPath(rel) || r.custom.MatchesPath(relSlash)) {
		return true
	}
	if r.defaults != nil && (r.defaults.MatchesPath(rel) || r.defaults.MatchesPath(relSlash)) {
		return true
	}
	for _, sm := range r.gitignores {
		sub, ok := relativeTo(sm.scopeDir, rel)
		if !ok {
			continue
		}
		subSlash := sub
		if !strings.HasSuffix(subSlash, "/") {
			subSlash = sub + "/"
		}
		if sm.matcher.MatchesPath(sub) || sm.matcher.MatchesPath(subSlash) {
			return true
		}
	}
	return false
}

// relativeTo returns (path-relative-to-scope, true) when `rel` is
// under `scope`. scope="" is the workdir root and matches everything.
// Returns ok=false when rel is OUTSIDE the scope (e.g. a sibling
// directory's .gitignore should never match paths outside its tree).
func relativeTo(scope, rel string) (string, bool) {
	if scope == "" {
		return rel, true
	}
	if rel == scope {
		return "", true
	}
	pfx := scope + "/"
	if !strings.HasPrefix(rel, pfx) {
		return "", false
	}
	return rel[len(pfx):], true
}
