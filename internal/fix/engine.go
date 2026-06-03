// Local fix engine — orchestrates detect → patch → apply for
// `getdebug fix --local-only`. The detector regex-scans the workdir,
// each hit is fed to its patcher, and the patcher's output is written
// back with a timestamped backup so `getdebug undo` (or a manual
// rollback) can restore the prior tree.
//
// Apply semantics:
//   - Backup directory at <workdir>/.getdebug-backup-<UTC-ts>/
//   - Source path copied into backup BEFORE the rewrite, mirroring the
//     same shape as the hosted-path applyPatch in cmd/fix.go so undo
//     works identically.
//   - A file is read once, patched once per matching detection (later
//     patches operate on the prior patcher's output — but each patcher
//     only rewrites a single line, so chained patches commute in
//     practice).
//   - On any write failure mid-run we DO NOT roll back already-written
//     files automatically. The backup directory remains and the user
//     can restore explicitly. The CLI surfaces this clearly.

package fix

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ApplyOutcome is the per-Detected result of an engine run. One entry
// per detected pattern, whether we ended up rewriting the file or not.
type ApplyOutcome struct {
	Detected      Detected
	OK            bool
	Description   string
	Reason        string
	ManualCommand string
}

// EngineResult is what `fix --local-only` reports back to the CLI for
// printing. Holds the backup path + the per-pattern outcomes.
type EngineResult struct {
	BackupDir string
	Outcomes  []ApplyOutcome
}

// Stats summarises the result for the CLI's footer line.
func (r EngineResult) Stats() (applied, declined, manual int, filesTouched int) {
	files := map[string]struct{}{}
	for _, o := range r.Outcomes {
		switch {
		case o.OK:
			applied++
			files[o.Detected.FilePath] = struct{}{}
		case o.ManualCommand != "":
			manual++
		default:
			declined++
		}
	}
	return applied, declined, manual, len(files)
}

// EngineOptions configures one engine run.
type EngineOptions struct {
	// Workdir is the directory the detector walks and the apply path
	// writes into. Must already be a directory; the engine doesn't
	// create it.
	Workdir string
	// DryRun = true: detect + run patchers but do NOT write to disk and
	// do NOT create a backup directory. Used for `--apply` previewing.
	DryRun bool
	// Logf is the optional progress logger (printed to stderr by the CLI).
	Logf func(format string, args ...any)
	// Now is injected for testability; nil = time.Now().
	Now func() time.Time
}

// Run drives the full pipeline: detect → group by file → for each
// file, in stable order, run every patcher whose detection landed
// there, accumulating the new source — then write once at the end.
//
// Backup writes ALWAYS precede source writes, so an abort partway
// through still leaves a usable rollback artifact.
func Run(opts EngineOptions) (EngineResult, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	info, err := os.Stat(opts.Workdir)
	if err != nil {
		return EngineResult{}, fmt.Errorf("workdir: %w", err)
	}
	if !info.IsDir() {
		return EngineResult{}, fmt.Errorf("workdir is not a directory: %s", opts.Workdir)
	}

	detections, err := Detect(opts.Workdir, logf)
	if err != nil {
		return EngineResult{}, fmt.Errorf("detect: %w", err)
	}

	if len(detections) == 0 {
		return EngineResult{Outcomes: nil}, nil
	}

	// Group by file so we read each file once and accumulate patches in
	// memory. Within a file, sort by LineStart so patcher-to-patcher
	// changes apply against a stable baseline (each patcher rewrites a
	// single line; sorting top-down keeps the line numbers meaningful).
	byFile := map[string][]Detected{}
	for _, d := range detections {
		byFile[d.FilePath] = append(byFile[d.FilePath], d)
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		sort.SliceStable(byFile[f], func(i, j int) bool {
			return byFile[f][i].LineStart < byFile[f][j].LineStart
		})
	}

	// Backup directory — only created if anything will actually be
	// written. The DryRun path skips this entirely.
	var backupDir string
	if !opts.DryRun {
		ts := now().UTC().Format("20060102T150405Z")
		backupDir = filepath.Join(opts.Workdir, fmt.Sprintf(".getdebug-backup-%s", ts))
		if err := os.MkdirAll(backupDir, 0o755); err != nil {
			return EngineResult{}, fmt.Errorf("create backup dir: %w", err)
		}
	}

	result := EngineResult{BackupDir: backupDir}

	for _, rel := range files {
		abs := filepath.Join(opts.Workdir, rel)
		raw, err := os.ReadFile(abs)
		if err != nil {
			// Detector saw the file; if we can't read it now, surface
			// every detection as declined and keep going.
			for _, d := range byFile[rel] {
				result.Outcomes = append(result.Outcomes, ApplyOutcome{
					Detected: d, OK: false,
					Reason: fmt.Sprintf("re-read failed: %v", err),
				})
			}
			continue
		}
		current := string(raw)
		fileChanged := false

		for _, d := range byFile[rel] {
			patcher := Lookup(d.Category)
			if patcher == nil {
				// Detector + patcher symmetry is enforced by tests, but
				// if a stale rule slipped through, decline honestly.
				result.Outcomes = append(result.Outcomes, ApplyOutcome{
					Detected: d, OK: false,
					Reason: fmt.Sprintf("no local patcher registered for %q", d.Category),
				})
				continue
			}
			pr := patcher(PatcherInput{
				Source:   current,
				FilePath: d.FilePath,
				Match: MatchSite{
					LineStart:   d.LineStart,
					LineEnd:     d.LineEnd,
					MatchedSpan: d.MatchedSpan,
				},
			})
			outcome := ApplyOutcome{
				Detected:      d,
				OK:            pr.OK,
				Description:   pr.Description,
				Reason:        pr.Reason,
				ManualCommand: pr.ManualCommand,
			}
			if pr.OK {
				current = pr.Patched
				fileChanged = true
			}
			result.Outcomes = append(result.Outcomes, outcome)
		}

		if opts.DryRun || !fileChanged {
			continue
		}

		// Backup BEFORE write — same safety rail the hosted path uses.
		dst := filepath.Join(backupDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return result, fmt.Errorf("mkdir backup for %s: %w", rel, err)
		}
		if err := copyFile(abs, dst); err != nil {
			return result, fmt.Errorf("backup %s: %w", rel, err)
		}
		// Preserve original mode bits so the write doesn't drop +x on a
		// script.
		mode := os.FileMode(0o644)
		if st, err := os.Stat(abs); err == nil {
			mode = st.Mode().Perm()
		}
		if err := os.WriteFile(abs, []byte(current), mode); err != nil {
			return result, fmt.Errorf("write %s: %w", rel, err)
		}
		logf("fix-local: patched %s", rel)
	}

	return result, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
