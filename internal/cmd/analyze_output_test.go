package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSARIFPath_AllowsNormal(t *testing.T) {
	cases := []string{
		"results.sarif",
		"./getdebug-results.sarif",
		"build/results.sarif",
		"/tmp/results.sarif",         // common CI artifact dir
		"/home/runner/work/x.sarif",  // GitHub Actions runner workspace
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if err := validateSARIFPath(p); err != nil {
				t.Errorf("validateSARIFPath(%q) = %v, want nil", p, err)
			}
		})
	}
}

func TestValidateSARIFPath_RejectsSystemDirs(t *testing.T) {
	cases := []string{
		"/etc/cron.d/backdoor",
		"/etc/passwd",
		"/bin/sh",
		"/sbin/init",
		"/usr/bin/anything",
		"/boot/grub.cfg",
		"/proc/self/mem",
		"/sys/kernel/x",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			err := validateSARIFPath(p)
			if err == nil {
				t.Fatalf("validateSARIFPath(%q) = nil, want error", p)
			}
			if !strings.Contains(err.Error(), "refusing") {
				t.Errorf("error = %q, want 'refusing'", err.Error())
			}
		})
	}
}

func TestValidateSARIFPath_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.sarif")
	link := filepath.Join(dir, "link.sarif")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported in this test env: %v", err)
	}

	err := validateSARIFPath(link)
	if err == nil {
		t.Fatal("validateSARIFPath accepted a symlink target; expected error")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %q, want it to mention 'symlink'", err.Error())
	}
}

func TestValidateSARIFPath_RejectsEmpty(t *testing.T) {
	if err := validateSARIFPath(""); err == nil {
		t.Error("validateSARIFPath(\"\") = nil, want error")
	}
}
