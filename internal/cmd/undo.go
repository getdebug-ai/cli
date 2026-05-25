package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var undoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Restore files modified by the most recent `getdebug fix --apply`",
	Long: `Reads the most recent .getdebug-backup-<timestamp>/ directory in the
current repo root and restores its contents over the working tree.

Files that were absent before the fix (pure additions) are deleted —
they're marked at backup time with a *.getdebug-was-absent sentinel.

If multiple backup directories exist (you applied several fixes without
undoing in between), --timestamp explicitly picks one; otherwise the
newest wins.`,
	RunE: runUndo,
}

var undoTimestamp string

func init() {
	undoCmd.Flags().StringVar(&undoTimestamp, "timestamp", "", "restore from .getdebug-backup-<TS> instead of the most recent")
}

func runUndo(cmd *cobra.Command, _ []string) error {
	root, err := gitRepoRoot()
	if err != nil {
		return fmt.Errorf("`getdebug undo` must run inside the project's git repo (%w)", err)
	}

	backupDir, err := pickBackupDir(root, undoTimestamp)
	if err != nil {
		return err
	}

	restored, deleted, err := restoreFrom(backupDir, root)
	if err != nil {
		return err
	}

	cmd.Printf("Restored %d file(s), deleted %d new file(s) from %s.\n",
		restored, deleted, filepath.Base(backupDir))
	cmd.Printf("Backup retained at %s — delete it manually if you don't need it.\n", backupDir)
	return nil
}

// pickBackupDir picks the requested timestamped backup, or the most recent
// one if no timestamp was given. Returns a clear error when nothing's
// available so the user knows there's nothing to undo.
func pickBackupDir(root, ts string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read repo root: %w", err)
	}
	const prefix = ".getdebug-backup-"
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		dirs = append(dirs, e.Name())
	}
	if len(dirs) == 0 {
		return "", errors.New("no .getdebug-backup-* directories found — nothing to undo")
	}
	if ts != "" {
		want := prefix + ts
		for _, d := range dirs {
			if d == want {
				return filepath.Join(root, d), nil
			}
		}
		return "", fmt.Errorf("no backup with timestamp %s — available: %s", ts, strings.Join(dirs, ", "))
	}
	// Newest first — timestamps are formatted YYYYMMDDTHHMMSSZ so lex sort
	// is chronological.
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	return filepath.Join(root, dirs[0]), nil
}

// restoreFrom walks the backup tree and copies every file back to the
// matching path under root, replacing whatever's there. *.getdebug-was-absent
// sentinels are interpreted as "this file didn't exist; delete it now."
func restoreFrom(backupDir, root string) (restored, deleted int, err error) {
	walkErr := filepath.WalkDir(backupDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(backupDir, p)
		if rerr != nil {
			return rerr
		}
		// Sentinel: the file was absent before fix --apply, so undo deletes it.
		if strings.HasSuffix(rel, ".getdebug-was-absent") {
			target := filepath.Join(root, strings.TrimSuffix(rel, ".getdebug-was-absent"))
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("delete %s: %w", target, err)
			}
			deleted++
			return nil
		}
		target := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir for restore: %w", err)
		}
		if err := copyFile(p, target); err != nil {
			return fmt.Errorf("restore %s: %w", rel, err)
		}
		restored++
		return nil
	})
	return restored, deleted, walkErr
}
