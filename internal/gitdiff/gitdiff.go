// Package gitdiff resolves the set of files changed in a diff, for diff-scoped
// scans (`getdebug analyze --diff-ref` / `--diff-file`). Paths are returned
// relative to the scan workdir (forward-slash), matching scanner
// Finding.FilePath, so a caller can both narrow the expensive passes and filter
// the final report to "only what this change touched" — the PR-gate use case.
package gitdiff

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedSet returns workdir-relative paths changed vs `ref` (a git ref) or
// listed in `diffFile` (a pre-generated unified diff). Exactly one of
// ref/diffFile should be non-empty; both is an error, neither returns (nil,nil)
// meaning "no diff scoping requested". Deleted files are excluded — there's
// nothing left to scan. A non-nil but empty map means "a diff was requested but
// nothing in scope changed" (callers treat that as a clean, zero-work scan).
func ChangedSet(workdir, ref, diffFile string) (map[string]bool, error) {
	switch {
	case ref != "" && diffFile != "":
		return nil, fmt.Errorf("use --diff-ref OR --diff-file, not both")
	case ref != "":
		return fromRef(workdir, ref)
	case diffFile != "":
		return fromDiffFile(workdir, diffFile)
	default:
		return nil, nil
	}
}

func fromRef(workdir, ref string) (map[string]bool, error) {
	// --relative scopes output to (and makes paths relative to) workdir, so a
	// finding's relative path matches directly; --diff-filter=d drops deleted
	// files (nothing to scan).
	out, err := exec.Command("git", "-C", workdir, "diff", "--name-only", "--relative", "--diff-filter=d", ref).Output()
	if err != nil {
		return nil, fmt.Errorf("git diff against %q failed — is %s inside a git repo and is the ref valid? (%w)", ref, workdir, err)
	}
	return toSet(splitLines(string(out))), nil
}

func fromDiffFile(workdir, diffFile string) (map[string]bool, error) {
	f, err := os.Open(diffFile)
	if err != nil {
		return nil, fmt.Errorf("open diff file: %w", err)
	}
	defer f.Close()
	rootRel := ParseUnifiedDiff(f) // repo-root-relative post-image paths

	// Diff paths are repo-root-relative; convert to workdir-relative and drop
	// anything outside the scan dir. If we can't find the repo root (git missing
	// or not a repo), best-effort: treat the diff paths as already relative.
	top, err := repoToplevel(workdir)
	if err != nil {
		return toSet(rootRel), nil
	}
	prefix, err := filepath.Rel(top, workdir)
	if err != nil {
		return toSet(rootRel), nil
	}
	prefix = filepath.ToSlash(prefix)

	set := make(map[string]bool, len(rootRel))
	for _, p := range rootRel {
		rel := p
		if prefix != "." {
			if !strings.HasPrefix(p, prefix+"/") {
				continue // changed file lives outside the scan dir
			}
			rel = strings.TrimPrefix(p, prefix+"/")
		}
		set[rel] = true
	}
	return set, nil
}

// ParseUnifiedDiff extracts the post-image (b/) paths from a unified diff.
// Deleted files (post-image /dev/null) are skipped; the `b/` prefix and any
// trailing tab-timestamp are stripped. Pure — unit-testable without git.
func ParseUnifiedDiff(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 32*1024*1024) // tolerate large diffs
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "+++ ") {
			continue
		}
		p := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
		if p == "/dev/null" {
			continue // deleted file — no post-image to scan
		}
		// Some diff tools append a tab + timestamp after the path.
		if i := strings.IndexByte(p, '\t'); i >= 0 {
			p = p[:i]
		}
		p = strings.TrimPrefix(p, "b/")
		if p != "" {
			out = append(out, filepath.ToSlash(p))
		}
	}
	return out
}

func repoToplevel(workdir string) (string, error) {
	out, err := exec.Command("git", "-C", workdir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, filepath.ToSlash(l))
		}
	}
	return out
}

func toSet(paths []string) map[string]bool {
	set := make(map[string]bool, len(paths))
	for _, p := range paths {
		set[p] = true
	}
	return set
}
