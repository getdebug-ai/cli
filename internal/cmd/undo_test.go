package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// FIX 17 (2026-06-06 dogfood): `getdebug undo` deletes the backup
// directory by default; --keep-backup retains it. The pre-fix behaviour
// always kept the backup, which surprised users — they expected "undo"
// to be a full reverse + cleanup.

// withUndoFlags is the same trick analyze_test uses — reset package-level
// flag globals around a test so runs don't pollute each other.
func withUndoFlags(t *testing.T, keep bool, timestamp string) {
	t.Helper()
	prevKeep, prevTS := undoKeepBackup, undoTimestamp
	t.Cleanup(func() {
		undoKeepBackup, undoTimestamp = prevKeep, prevTS
	})
	undoKeepBackup = keep
	undoTimestamp = timestamp
}

// setupRepoWithBackup creates a temp dir, runs `git init`, plants a
// .getdebug-backup-<ts> directory with one file inside, and chdirs into
// the repo. Returns the repo root and the backup dir path.
func setupRepoWithBackup(t *testing.T, ts string) (string, string) {
	t.Helper()
	root := t.TempDir()
	if out, err := exec.Command("git", "init", "--initial-branch=main", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	// Plant the original file so `restore` has something to write back to.
	if err := os.WriteFile(filepath.Join(root, "hello.go"), []byte("modified\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(root, ".getdebug-backup-"+ts)
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "hello.go"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prevWd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	return root, backupDir
}

func fakeUndoCmd() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	c := &cobra.Command{Use: "undo"}
	c.SetOut(&stdout)
	c.SetErr(&stderr)
	return c, &stdout, &stderr
}

func TestRunUndo_DefaultDeletesBackup(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	withUndoFlags(t, false /* keep */, "")
	root, backupDir := setupRepoWithBackup(t, "20260606T120000Z")

	c, stdout, _ := fakeUndoCmd()
	if err := runUndo(c, nil); err != nil {
		t.Fatalf("runUndo: %v", err)
	}
	// Restore happened.
	if got, err := os.ReadFile(filepath.Join(root, "hello.go")); err != nil || string(got) != "original\n" {
		t.Errorf("restore did not write original content; got %q err=%v", got, err)
	}
	// Backup is gone.
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Errorf("backup dir %s still exists after default undo (err=%v) — FIX 17 regression", backupDir, err)
	}
	if !strings.Contains(stdout.String(), "Removed backup") {
		t.Errorf("output should mention removing the backup; got:\n%s", stdout.String())
	}
}

func TestRunUndo_KeepBackupRetainsDir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	withUndoFlags(t, true /* keep */, "")
	_, backupDir := setupRepoWithBackup(t, "20260606T130000Z")

	c, stdout, _ := fakeUndoCmd()
	if err := runUndo(c, nil); err != nil {
		t.Fatalf("runUndo: %v", err)
	}
	if _, err := os.Stat(backupDir); err != nil {
		t.Errorf("backup dir %s removed despite --keep-backup (err=%v)", backupDir, err)
	}
	if !strings.Contains(stdout.String(), "kept at") {
		t.Errorf("output should mention the backup was kept; got:\n%s", stdout.String())
	}
}
