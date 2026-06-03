package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// End-to-end smoke test for the detect → patch → apply pipeline.
// Seeds a synthetic workdir with three plant-able patterns across two
// files, runs the engine, and asserts that the right things were
// written to the right places — including the backup directory.
func TestEngineRunAppliesPatchesAndCreatesBackup(t *testing.T) {
	tmp := t.TempDir()

	// File 1: weak-crypto + insecure-random. Two patches on one file.
	jsPath := filepath.Join(tmp, "src", "lib.ts")
	if err := os.MkdirAll(filepath.Dir(jsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	originalJS := `import crypto from "crypto";
export function token() {
  const id = crypto.createHash("md5").update("x").digest("hex");
  const jitter = Math.random();
  return id + jitter;
}
`
	if err := os.WriteFile(jsPath, []byte(originalJS), 0o644); err != nil {
		t.Fatal(err)
	}

	// File 2: xss-shaped innerHTML write.
	xssPath := filepath.Join(tmp, "src", "ui.ts")
	originalXSS := `function render(el, txt) { el.innerHTML = txt; }`
	if err := os.WriteFile(xssPath, []byte(originalXSS), 0o644); err != nil {
		t.Fatal(err)
	}

	// File 3: a Python file with a hashlib hit.
	pyPath := filepath.Join(tmp, "scripts", "hash.py")
	if err := os.MkdirAll(filepath.Dir(pyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	originalPY := "import hashlib\n\ndef k(s): return hashlib.md5(s).hexdigest()\n"
	if err := os.WriteFile(pyPath, []byte(originalPY), 0o644); err != nil {
		t.Fatal(err)
	}

	frozen := time.Date(2026, 6, 3, 23, 30, 0, 0, time.UTC)
	res, err := Run(EngineOptions{
		Workdir: tmp,
		DryRun:  false,
		Now:     func() time.Time { return frozen },
	})
	if err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	applied, _, _, files := res.Stats()
	if applied != 4 {
		t.Errorf("expected 4 patches applied (md5, Math.random, innerHTML, hashlib.md5); got %d", applied)
	}
	if files != 3 {
		t.Errorf("expected 3 files touched, got %d", files)
	}

	// Backup directory exists at the expected timestamped path.
	wantBackup := filepath.Join(tmp, ".getdebug-backup-20260603T233000Z")
	if res.BackupDir != wantBackup {
		t.Errorf("backup dir = %q, want %q", res.BackupDir, wantBackup)
	}
	if _, err := os.Stat(wantBackup); err != nil {
		t.Errorf("backup dir not created: %v", err)
	}
	// Backups preserve workdir-relative structure.
	if _, err := os.Stat(filepath.Join(wantBackup, "src", "lib.ts")); err != nil {
		t.Errorf("expected lib.ts in backup: %v", err)
	}
	// And the backup content is the ORIGINAL.
	if got, _ := os.ReadFile(filepath.Join(wantBackup, "src", "lib.ts")); string(got) != originalJS {
		t.Errorf("backup did not preserve original content")
	}

	// Patched files no longer contain the vulnerable patterns.
	jsAfter, _ := os.ReadFile(jsPath)
	if strings.Contains(string(jsAfter), `"md5"`) {
		t.Errorf("md5 still present after patch:\n%s", jsAfter)
	}
	if strings.Contains(string(jsAfter), "Math.random()") {
		t.Errorf("Math.random() still present after patch:\n%s", jsAfter)
	}
	if !strings.Contains(string(jsAfter), `"sha256"`) {
		t.Errorf("sha256 missing after patch:\n%s", jsAfter)
	}
	xssAfter, _ := os.ReadFile(xssPath)
	if !strings.Contains(string(xssAfter), "el.textContent = txt") {
		t.Errorf("xss patch did not land:\n%s", xssAfter)
	}
	pyAfter, _ := os.ReadFile(pyPath)
	if strings.Contains(string(pyAfter), "hashlib.md5") {
		t.Errorf("python md5 still present:\n%s", pyAfter)
	}
}

func TestEngineDryRunDoesNotWrite(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "x.ts")
	src := `const r = Math.random();`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(EngineOptions{Workdir: tmp, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.BackupDir != "" {
		t.Errorf("DryRun should not create a backup dir, got %q", res.BackupDir)
	}
	// File untouched.
	after, _ := os.ReadFile(path)
	if string(after) != src {
		t.Errorf("DryRun mutated the file: got %q want %q", after, src)
	}
	// But outcomes still report what WOULD have been patched.
	applied, _, _, _ := res.Stats()
	if applied != 1 {
		t.Errorf("expected 1 patch reported (dry-run), got %d", applied)
	}
}

// Vendor and lockfile dirs must be skipped — a Math.random() inside
// node_modules is not the user's code and patching it would silently
// drift on the next install.
func TestEngineSkipsVendorDirs(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "node_modules", "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	vendored := filepath.Join(tmp, "node_modules", "vendor", "x.js")
	if err := os.WriteFile(vendored, []byte(`Math.random();`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(EngineOptions{Workdir: tmp, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) != 0 {
		t.Errorf("expected no outcomes (node_modules skipped), got %d", len(res.Outcomes))
	}
}

// A workdir with no patterns reports cleanly — no error, no backup
// directory created.
func TestEngineCleanWorkdirReportsNothing(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "ok.ts"), []byte("export const x = 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(EngineOptions{Workdir: tmp, DryRun: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) != 0 {
		t.Errorf("expected no outcomes on clean repo, got %d", len(res.Outcomes))
	}
	if res.BackupDir != "" {
		t.Errorf("clean repo should not produce a backup dir; got %q", res.BackupDir)
	}
}

// File-permission preservation — patching a +x script must leave the
// file executable. Otherwise applying a fix to a CLI shim or a hook
// silently breaks it.
func TestEnginePreservesFilePermissions(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "script.js")
	src := `console.log(Math.random());`
	if err := os.WriteFile(path, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(EngineOptions{Workdir: tmp, DryRun: false}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("execute bit dropped after patch: mode=%v", info.Mode().Perm())
	}
}

// Detect-only sanity: a file with all four high-signal categories
// produces one detection per category.
func TestDetectorEmitsOnePerCategory(t *testing.T) {
	src := `import crypto from "crypto";
const cors = { "Access-Control-Allow-Origin": "*" };
const r = Math.random();
const h = crypto.createHash("md5");
el.innerHTML = txt;
`
	hits := scanFile("src/lib.ts", ".ts", src)
	seen := map[string]int{}
	for _, h := range hits {
		seen[h.Category]++
	}
	for _, cat := range []string{"weak-crypto", "insecure-random", "xss", "insecure-cors"} {
		if seen[cat] != 1 {
			t.Errorf("expected one %s detection, got %d", cat, seen[cat])
		}
	}
}

// Detector→patcher symmetry: every category the detector emits MUST
// resolve to a patcher in the registry. Without this, the engine would
// surface "detected but unfixable" for our own categories — a bug.
func TestDetectorAndPatcherSymmetry(t *testing.T) {
	for _, rule := range detectorRules {
		if Lookup(rule.Category) == nil {
			t.Errorf("detector emits %q but no patcher is registered", rule.Category)
		}
	}
}
