package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/config"
)

var (
	fixApply       bool
	fixInteractive bool
	fixLocalOnly   bool
	fixCI          bool
)

var fixCmd = &cobra.Command{
	Use:   "fix [fix-id]",
	Short: "Show or apply a getdebug-generated fix",
	Long: `Without an argument: lists fixes proposed for your org (the same ones
visible in the dashboard's Fixes tab), so you can pick one to apply
locally.

With a fix id: fetches the unified diff and prints it. Pass --apply to
write it to your working tree.

` + "`getdebug fix <id> --apply`" + ` does, in order:

  1. Fetches the patch from the api.
  2. Identifies every file the patch touches and copies the current
     contents to .getdebug-backup-<timestamp>/<original-path>.
  3. Runs ` + "`git apply --check`" + ` to validate the patch cleanly applies.
  4. Runs ` + "`git apply`" + ` to actually write the changes.
  5. On any failure during 3-4 nothing is left half-applied — your tree
     is exactly where it started.

Run ` + "`getdebug undo`" + ` to restore the most-recent backup.

Security-sensitive categories (secrets, sql-injection, command-injection,
ssrf, missing-auth, broken-access) are policy-protected upstream: the
api never returns a patch for them, so this command can't apply one
either. The dashboard surfaces them with explanation only.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFix,
}

func init() {
	fixCmd.Flags().BoolVar(&fixApply, "apply", false, "write the patch to disk (default: dry-run preview)")
	fixCmd.Flags().BoolVar(&fixInteractive, "interactive", false, "walk through pending fixes one by one (Phase 2)")
	fixCmd.Flags().BoolVar(&fixLocalOnly, "local-only", false, "use your own Claude key, never upload (Phase 2)")
	fixCmd.Flags().BoolVar(&fixCI, "ci", false, "exit non-zero on any unfixed finding above threshold (Phase 2)")
}

type fixListItem struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	Finding   struct {
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Category  string `json:"category"`
		FilePath  string `json:"filePath"`
		LineStart int    `json:"lineStart"`
	} `json:"finding"`
	Project struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"`
	PullRequest *struct {
		URL    string `json:"url"`
		Status string `json:"status"`
		Branch string `json:"branch"`
	} `json:"pullRequest"`
}

type fixPatchResp struct {
	Patch      string         `json:"patch"`
	Status     string         `json:"status"`
	Confidence *int           `json:"confidence"`
	Validation map[string]any `json:"validation"`
	Finding    struct {
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Category  string `json:"category"`
		FilePath  string `json:"filePath"`
		LineStart int    `json:"lineStart"`
		LineEnd   int    `json:"lineEnd"`
	} `json:"finding"`
	Project struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		SourceRef string `json:"sourceRef"`
	} `json:"project"`
}

func runFix(cmd *cobra.Command, args []string) error {
	if fixInteractive || fixLocalOnly || fixCI {
		return errors.New("--interactive, --local-only, --ci are not yet implemented (Phase 2)")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Token == "" || cfg.APIBaseURL == "" {
		cmd.PrintErrln("Not logged in. Run `getdebug login` first.")
		os.Exit(1)
	}

	if len(args) == 0 {
		return listFixes(cmd, cfg)
	}
	return showOrApplyFix(cmd, cfg, args[0])
}

func listFixes(cmd *cobra.Command, cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()

	var resp struct {
		Fixes []fixListItem `json:"fixes"`
	}
	if err := apiGet(ctx, cfg, "/v1/fixes?status=proposed&limit=20", &resp); err != nil {
		return err
	}
	if len(resp.Fixes) == 0 {
		cmd.Println("No fixes pending. Either there are no fixable findings, or all current fixes have been applied/rejected.")
		return nil
	}
	cmd.Printf("Pending fixes (showing %d):\n\n", len(resp.Fixes))
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  FIX ID\tPROJECT\tSEVERITY\tFILE\tTITLE")
	for _, f := range resp.Fixes {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s:%d\t%s\n",
			truncate(f.ID, 18),
			truncate(f.Project.Name, 18),
			f.Finding.Severity,
			truncate(f.Finding.FilePath, 32),
			f.Finding.LineStart,
			truncate(f.Finding.Title, 48),
		)
	}
	tw.Flush()
	cmd.Println()
	cmd.Println("Inspect with:  getdebug fix <fix-id>")
	cmd.Println("Apply with:    getdebug fix <fix-id> --apply")
	return nil
}

func showOrApplyFix(cmd *cobra.Command, cfg *config.Config, fixID string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
	defer cancel()
	var resp fixPatchResp
	if err := apiGet(ctx, cfg, "/v1/fixes/"+fixID+"/patch", &resp); err != nil {
		return err
	}
	if strings.TrimSpace(resp.Patch) == "" {
		return fmt.Errorf("fix %s has no patch (status=%s)", fixID, resp.Status)
	}

	cmd.Printf("Fix %s · %s · %s:%d\n", fixID, resp.Finding.Severity, resp.Finding.FilePath, resp.Finding.LineStart)
	cmd.Printf("  %s (%s)\n\n", resp.Finding.Title, resp.Finding.Category)

	if !fixApply {
		printPatch(cmd.OutOrStdout(), resp.Patch)
		cmd.Println()
		cmd.Printf("Dry run. Re-run with --apply to write to disk.\n")
		return nil
	}

	return applyPatch(cmd, fixID, &resp)
}

func applyPatch(cmd *cobra.Command, fixID string, fp *fixPatchResp) error {
	files, err := filesFromPatch(fp.Patch)
	if err != nil {
		return fmt.Errorf("parse patch: %w", err)
	}
	if len(files) == 0 {
		return errors.New("patch touches no files — refusing to apply")
	}

	// Establish working dir. We expect to be inside a git work tree so
	// `git apply` works; the patch's paths are relative to repo root.
	root, err := gitRepoRoot()
	if err != nil {
		return fmt.Errorf("`getdebug fix --apply` must run inside the project's git repo (%w)", err)
	}

	// Sanity-check the patch is for THIS repo. We compare project.sourceRef
	// (`owner/repo`) against the basename of the current repo's remote
	// origin URL. Soft check — warn on mismatch, don't block; some users
	// rename repos locally.
	if remote := gitRemoteOriginBase(); remote != "" && fp.Project.SourceRef != "" {
		if !strings.EqualFold(remote, fp.Project.SourceRef) {
			cmd.PrintErrf(
				"Warning: this fix is for %s but the current repo's origin looks like %s. Continuing — pass Ctrl+C to abort within 3s.\n",
				fp.Project.SourceRef, remote,
			)
			time.Sleep(3 * time.Second)
		}
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	backupDir := filepath.Join(root, fmt.Sprintf(".getdebug-backup-%s", ts))
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	for _, rel := range files {
		src := filepath.Join(root, rel)
		dst := filepath.Join(backupDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("mkdir for backup: %w", err)
		}
		// Skip files that don't exist yet (pure additions). Mark them with
		// an empty placeholder so undo knows to delete on restore.
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			f, ferr := os.Create(dst + ".getdebug-was-absent")
			if ferr != nil {
				return fmt.Errorf("mark absent: %w", ferr)
			}
			f.Close()
			continue
		} else if err != nil {
			return fmt.Errorf("stat %s: %w", src, err)
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("backup %s: %w", rel, err)
		}
	}

	// Validate then apply via git. --check exits non-zero if the patch
	// won't apply cleanly without writing anything; the second call does
	// the write. We pipe the patch to stdin both times.
	if err := gitApply(root, fp.Patch, true); err != nil {
		// Roll back the backup dir we just made — the apply never happened.
		_ = os.RemoveAll(backupDir)
		return fmt.Errorf("git apply --check failed; tree unchanged (%w)", err)
	}
	if err := gitApply(root, fp.Patch, false); err != nil {
		// Same: nothing was written if git apply errored out cleanly.
		_ = os.RemoveAll(backupDir)
		return fmt.Errorf("git apply failed; tree unchanged (%w)", err)
	}

	cmd.Printf("Applied fix %s to %d file(s).\n", fixID, len(files))
	cmd.Printf("Backup: %s\n", backupDir)
	cmd.Println("Restore with: getdebug undo")
	return nil
}

// ─── HTTP helper ────────────────────────────────────────────────

func apiGet(ctx context.Context, cfg *config.Config, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.APIBaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	var env struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data,omitempty"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("decode envelope: %w (body=%s)", err, string(body))
	}
	if !env.OK {
		if env.Error != nil && env.Error.Code == "unauthorized" {
			fmt.Fprintln(os.Stderr, "Your token was rejected. Run `getdebug login` to re-authenticate.")
			os.Exit(1)
		}
		if env.Error != nil {
			return fmt.Errorf("api: %s: %s", env.Error.Code, env.Error.Message)
		}
		return errors.New("api: unknown error")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}
	return nil
}

// ─── git + diff helpers ─────────────────────────────────────────

func gitRepoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitRemoteOriginBase returns "owner/repo" derived from origin URL, or "".
func gitRemoteOriginBase() string {
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	url := strings.TrimSpace(string(out))
	url = strings.TrimSuffix(url, ".git")
	if strings.HasPrefix(url, "git@") {
		// git@github.com:owner/repo
		i := strings.Index(url, ":")
		if i > 0 {
			return url[i+1:]
		}
	}
	// https://github.com/owner/repo
	parts := strings.Split(url, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return ""
}

func gitApply(root, patch string, checkOnly bool) error {
	args := []string{"apply"}
	if checkOnly {
		args = append(args, "--check")
	}
	args = append(args, "-")
	c := exec.Command("git", args...)
	c.Dir = root
	c.Stdin = strings.NewReader(patch)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// filesFromPatch pulls every distinct file path the unified diff touches.
// Handles two formats the fix worker may emit:
//
//   • git-style:  `+++ b/path/to/file`
//   • jsdiff-style (structured-patch): `+++ path/to/file\tafter`
//
// We read the `+++` (post-change) line because that's what matters for
// backup. /dev/null indicates a deletion; we skip it.
//
// Every returned path is validated to be a repo-relative path that does
// not escape via `..` or absolute roots. A patch from a compromised API
// (or a MITM'd `--api http://...`) could otherwise drive the backup loop
// in applyPatch to read or write arbitrary files under the user's UID
// before git's own path checks ever ran.
func filesFromPatch(patch string) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	for _, line := range strings.Split(patch, "\n") {
		if !strings.HasPrefix(line, "+++ ") {
			continue
		}
		p := strings.TrimPrefix(line, "+++ ")
		// Drop the git `b/` prefix if present.
		p = strings.TrimPrefix(p, "b/")
		// Strip the trailing tab+label (jsdiff adds `\tafter`; git diff
		// can add `\t<timestamp>`).
		if i := strings.Index(p, "\t"); i > 0 {
			p = p[:i]
		}
		p = strings.TrimSpace(p)
		if p == "" || p == "/dev/null" {
			continue
		}
		if err := validateRepoRelPath(p); err != nil {
			return nil, fmt.Errorf("patch references unsafe path %q: %w", p, err)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

// validateRepoRelPath rejects patch paths that aren't repo-relative.
// Disallows: absolute paths, drive-letter paths, paths containing `..`
// segments, paths with a leading separator, and Windows-style backslashes
// (which `filepath.Clean` doesn't normalize on Unix but `os.Open` may
// still treat as part of the filename). The check must happen on the raw
// string — `filepath.Clean` would silently fold `a/../etc` into `etc`
// and hide the intent.
func validateRepoRelPath(p string) error {
	if p == "" {
		return errors.New("empty path")
	}
	if filepath.IsAbs(p) {
		return errors.New("absolute path")
	}
	// Windows drive letters slip past filepath.IsAbs on Unix builds.
	if len(p) >= 2 && p[1] == ':' {
		return errors.New("drive-letter path")
	}
	// Reject backslash-as-separator paths outright: we can't tell on Unix
	// what the user's filesystem will do with them, and they're never a
	// legitimate git diff path.
	if strings.ContainsRune(p, '\\') {
		return errors.New("backslash in path")
	}
	cleaned := filepath.ToSlash(filepath.Clean(p))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return errors.New("path escapes repo root")
	}
	if strings.HasPrefix(cleaned, "/") {
		return errors.New("leading slash")
	}
	return nil
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
		out.Close()
		return err
	}
	return out.Close()
}

// printPatch ANSI-colors added/removed lines so the diff is scannable in
// a terminal. Hunk headers stay neutral; file headers stay neutral.
func printPatch(w io.Writer, patch string) {
	const (
		green = "\033[32m"
		red   = "\033[31m"
		cyan  = "\033[36m"
		reset = "\033[0m"
	)
	// NO_COLOR convention: respect it when set.
	useColor := os.Getenv("NO_COLOR") == ""
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "diff "):
			if useColor {
				fmt.Fprintf(w, "%s%s%s\n", cyan, line, reset)
			} else {
				fmt.Fprintln(w, line)
			}
		case strings.HasPrefix(line, "+"):
			if useColor {
				fmt.Fprintf(w, "%s%s%s\n", green, line, reset)
			} else {
				fmt.Fprintln(w, line)
			}
		case strings.HasPrefix(line, "-"):
			if useColor {
				fmt.Fprintf(w, "%s%s%s\n", red, line, reset)
			} else {
				fmt.Fprintln(w, line)
			}
		default:
			fmt.Fprintln(w, line)
		}
	}
}
