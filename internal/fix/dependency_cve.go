// Patcher: dependency-cve (per-CVE CWE).
//
// Port of workers/src/fix/patchers/dependency-cve.ts. Bump a vulnerable
// dependency to the advisory's fixed version. The detector
// (cli/internal/scan/deps.go and its hosted twin) attaches packageName
// + fixedVersion to the finding context; this patcher reads them and
// rewrites the pin in the manifest.
//
// v1 scope: **Python `requirements.txt` only**. Other ecosystems the
// deps detector covers (`pnpm-lock.yaml`, `package-lock.json`,
// `yarn.lock`, `go.mod`) defer:
//
//   - JS lockfiles carry integrity hashes (`integrity: sha512-…`) that
//     the lockfile generator computes from the registry. Rewriting the
//     version by hand leaves a corrupt lockfile. The correct fix is
//     `pnpm update <pkg>` / `npm install <pkg>@<ver>` — a build step.
//   - `go.mod` would be in scope shape-wise, but the matched fix
//     usually also requires updating `go.sum`. Same two-file
//     consistency problem.
//
// For deferred ecosystems the patcher returns a ManualCommand so the
// CLI can surface the exact command instead of silently dropping the
// finding.

package fix

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reqTxtFileRe = regexp.MustCompile(`(?i)(?:^|/)requirements(?:-[\w.]+)?\.txt$`)
	// PEP-508-ish: <name>[extras]==<version>[; markers] with optional
	// surrounding whitespace and trailing comment.
	// Capture groups: 1=leading ws, 2=name, 3=extras (incl. brackets),
	// 4=`==` with surrounding ws, 5=version, 6=trailing.
	reqPinRe = regexp.MustCompile(`^(\s*)([A-Za-z0-9][\w.\-]*)(\[[^\]]*\])?(\s*==\s*)([^\s;#]+)(.*)$`)
	// Strip leading range operators from a fixedVersion to get a clean pin.
	versionOpRe = regexp.MustCompile(`^(?:>=|>|~=|==)\s*`)
)

// DependencyCvePatcher rewrites a single `==`-pin in requirements.txt
// to the advisory's fixed version. Lockfile and go.mod hits return a
// manual-command result for the CLI to surface.
func DependencyCvePatcher(in PatcherInput) PatcherResult {
	if in.Context == nil {
		return PatcherResult{Reason: "no finding context — patcher needs packageName + fixedVersion"}
	}
	packageName := strings.TrimSpace(in.Context["packageName"])
	fixedVersionRaw := strings.TrimSpace(in.Context["fixedVersion"])
	if packageName == "" || fixedVersionRaw == "" {
		return PatcherResult{Reason: "finding context missing packageName or fixedVersion — patcher can't proceed"}
	}
	fixedVersion := extractCleanVersion(fixedVersionRaw)
	if fixedVersion == "" {
		return PatcherResult{
			Reason: fmt.Sprintf(`fixedVersion %q doesn't look like a concrete version — manual review needed`, fixedVersionRaw),
		}
	}

	switch {
	case strings.HasSuffix(in.FilePath, "pnpm-lock.yaml"),
		strings.HasSuffix(in.FilePath, "package-lock.json"),
		strings.HasSuffix(in.FilePath, "yarn.lock"):
		tool := "npm"
		switch {
		case strings.HasSuffix(in.FilePath, "yarn.lock"):
			tool = "yarn"
		case strings.HasSuffix(in.FilePath, "pnpm-lock.yaml"):
			tool = "pnpm"
		}
		cmd := fmt.Sprintf("npm install %s@%s", packageName, fixedVersion)
		switch tool {
		case "yarn":
			cmd = fmt.Sprintf("yarn up %s@%s", packageName, fixedVersion)
		case "pnpm":
			cmd = fmt.Sprintf("pnpm update %s@%s", packageName, fixedVersion)
		}
		return PatcherResult{
			Reason: fmt.Sprintf(
				"%s is a %s lockfile with integrity hashes the patcher can't recompute — run the command below locally and commit both manifest and lockfile.",
				in.FilePath, tool,
			),
			ManualCommand: cmd,
		}
	case strings.HasSuffix(in.FilePath, "go.mod"):
		return PatcherResult{
			Reason: fmt.Sprintf(
				"%s bumps need a paired `go.sum` rewrite the patcher doesn't perform. Run the commands below locally and commit both files.",
				in.FilePath,
			),
			ManualCommand: fmt.Sprintf("go get %s@v%s && go mod tidy", packageName, fixedVersion),
		}
	}

	if !reqTxtFileRe.MatchString(in.FilePath) {
		return PatcherResult{Reason: fmt.Sprintf("unsupported manifest: %s", in.FilePath)}
	}

	target := normalizePyName(packageName)
	lines := strings.Split(in.Source, "\n")
	hitLine := -1
	alreadyMet := false
	original := ""
	patchedLine := ""

	for i, line := range lines {
		m := reqPinRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		leading, name, extras, sep, version, trailing := m[1], m[2], m[3], m[4], m[5], m[6]
		if normalizePyName(name) != target {
			continue
		}
		if hitLine != -1 {
			return PatcherResult{
				Reason: fmt.Sprintf("requirements.txt has multiple pins for %s (lines %d and %d) — manual fix recommended", packageName, hitLine+1, i+1),
			}
		}
		hitLine = i
		original = line
		if version == fixedVersion {
			alreadyMet = true
			continue
		}
		patchedLine = leading + name + extras + sep + fixedVersion + trailing
	}

	if hitLine == -1 {
		return PatcherResult{
			Reason: fmt.Sprintf(
				"requirements.txt has no `==` pin for %s — it may use a range operator (>=, ~=) the v1 patcher doesn't rewrite, or the dependency is transitive",
				packageName,
			),
		}
	}
	if alreadyMet {
		return PatcherResult{
			Reason: fmt.Sprintf("%s is already pinned at %s on line %d — finding may be stale", packageName, fixedVersion, hitLine+1),
		}
	}

	out := make([]string, 0, len(lines))
	out = append(out, lines[:hitLine]...)
	out = append(out, patchedLine)
	out = append(out, lines[hitLine+1:]...)

	oldVersion := reqPinRe.FindStringSubmatch(original)[5]
	desc := strings.Join([]string{
		fmt.Sprintf("Bumped `%s` from %s to %s in %s", packageName, oldVersion, fixedVersion, in.FilePath),
		fmt.Sprintf("(line %d). This closes the advisory referenced in the finding.", hitLine+1),
		"",
		"Before merging: run `pip install -r " + in.FilePath + "` to verify the new version",
		"resolves and the rest of the dependency tree is still consistent. If you have",
		"a lockfile (`requirements.lock`, `Pipfile.lock`, `poetry.lock`) generated from",
		"this manifest, regenerate it as part of the same PR.",
	}, "\n")

	return PatcherResult{OK: true, Patched: strings.Join(out, "\n"), Description: desc}
}

// extractCleanVersion strips leading range operators (`>=`, `>`, `~=`,
// `==`) from a raw fixedVersion and returns the bare PEP-440 version.
// Returns "" when the input doesn't look like a concrete version.
func extractCleanVersion(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	stripped := versionOpRe.ReplaceAllString(trimmed, "")
	// Drop anything after a comma (compound ranges like ">=1.2.6,<2").
	head := strings.TrimSpace(strings.SplitN(stripped, ",", 2)[0])
	if head == "" || !(head[0] >= '0' && head[0] <= '9') {
		return ""
	}
	return head
}

// normalizePyName applies PEP 503 normalisation so `Flask-Login`,
// `flask_login`, `Flask.Login` all match.
func normalizePyName(raw string) string {
	lower := strings.ToLower(raw)
	var b strings.Builder
	b.Grow(len(lower))
	lastDash := false
	for _, r := range lower {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return b.String()
}
