package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/getdebug-ai/cli/internal/gitdiff"
	"github.com/getdebug-ai/cli/internal/localllm"
	"github.com/getdebug-ai/cli/internal/report"
	"github.com/getdebug-ai/cli/internal/scan"
)

var (
	analyzeNoGitignore      bool
	analyzeNoDefaultIgnores bool
	analyzeWatch            bool
	analyzeCI               bool
	analyzeFailOn           string
	analyzeSARIF            string
	analyzeJSON             bool
	analyzeQuiet            bool
	analyzeLocalLLM         bool
	analyzeLocalLLMModel    string
	analyzeLocalLLMMax      int
	analyzeLocalLLMTimeout  time.Duration
	analyzeVerify           bool
	analyzeOnlyVerified     bool
	analyzeDiffRef          string
	analyzeDiffFile         string
)

// ErrCIThresholdExceeded is returned by runAnalyze when --ci is set and at
// least one finding lands at or above the --fail-on threshold. main.go
// translates it into a silent exit(1) so CI logs aren't doubled-up by the
// generic error printer.
var ErrCIThresholdExceeded = errors.New("getdebug: ci threshold exceeded")

// validFailOnLevels mirrors the docs: critical | high | medium | low | any.
// "any" means anything above `info` — fail on every concrete finding.
// `verified-critical` / `verified-high` are the opt-in cousins of
// `critical` / `high` — same severity bucket, but skip secret findings
// whose verification status is `invalid`. Requires --verify (default on).
var validFailOnLevels = map[string]struct{}{
	"critical":          {},
	"high":              {},
	"medium":            {},
	"low":               {},
	"any":               {},
	"verified-critical": {},
	"verified-high":     {},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [path]",
	Short: "Scan a directory for security findings",
	Long: `Walks the given path (default: current directory) and runs getdebug's
local detectors. The secrets pass (regex + entropy) always runs — it
catches the highest-severity launch blockers (AWS / GitHub / Stripe / OpenAI
keys, private key blocks, high-entropy strings near credential keywords).

With --local-llm an AI-based SAST pass runs against a LOCAL Ollama chat
model (Qwen, DeepSeek, Llama, …) so code never leaves the laptop and you
pay nothing per scan. Coverage: 12 traditional SAST categories
(sql-injection, command-injection, path-traversal, xss, ssrf,
insecure-deserialize, weak-crypto, insecure-random, missing-auth,
broken-access, open-redirect, insecure-cors) AND 6 AI-app categories
(prompt-injection, unsafe-tool-output, pii-in-prompt, unsafe-role-merge,
client-side-llm-key, unbounded-stream).

Install Ollama (https://ollama.ai) and pull a model first:
'ollama pull qwen2.5-coder:7b'. Use --local-llm-model to override.

Exit codes:
  0  no findings, or findings below the --fail-on threshold
  1  findings at or above --fail-on threshold (only when --ci is set)
  2  fatal scan error

Examples:
  # Local scan, pretty output:
  getdebug analyze .

  # Local secrets + local-LLM SAST (Ollama):
  getdebug analyze . --local-llm

  # Same, with a stronger model + bigger budget:
  getdebug analyze . --local-llm --local-llm-model=deepseek-r1:7b --local-llm-max-files=200

  # CI gate — fail the build on any critical finding:
  getdebug analyze . --ci --fail-on=critical

  # Emit SARIF for GitHub Code Scanning:
  getdebug analyze . --sarif=getdebug-results.sarif`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&analyzeNoGitignore, "no-gitignore", false,
		"scan files even when they match .gitignore (default: respect .gitignore, matching the hosted scan)")
	analyzeCmd.Flags().BoolVar(&analyzeNoDefaultIgnores, "no-default-ignores", false,
		"scan test files / fixtures / snapshots the CLI excludes by default (**/*.test.*, **/*_test.go, **/__tests__/**, etc.)")
	analyzeCmd.Flags().BoolVar(&analyzeWatch, "watch", false, "re-analyze on file changes (Phase 2 — not yet implemented)")
	analyzeCmd.Flags().BoolVar(&analyzeCI, "ci", false, "exit non-zero on findings at or above --fail-on threshold")
	analyzeCmd.Flags().StringVar(&analyzeFailOn, "fail-on", "high", "minimum severity that fails the build under --ci: critical|high|medium|low|any|verified-critical|verified-high")
	analyzeCmd.Flags().StringVar(&analyzeSARIF, "sarif", "", "write SARIF 2.1.0 results to this path (for GitHub Code Scanning)")
	analyzeCmd.Flags().BoolVar(&analyzeJSON, "json", false, "emit findings as newline-delimited JSON instead of the table")
	analyzeCmd.Flags().BoolVar(&analyzeQuiet, "quiet", false, "suppress the scan-progress banner")
	analyzeCmd.Flags().BoolVar(&analyzeLocalLLM, "local-llm", false,
		"also run an AI-based SAST pass using a LOCAL Ollama chat model (code never leaves the laptop)")
	analyzeCmd.Flags().StringVar(&analyzeLocalLLMModel, "local-llm-model", "",
		"Ollama model for --local-llm (default: qwen2.5-coder:7b). Examples: deepseek-r1:7b, llama3.1:8b")
	analyzeCmd.Flags().IntVar(&analyzeLocalLLMMax, "local-llm-max-files", 0,
		"cap files sent to the local model in one scan (default 50). Higher = more coverage, longer wall-clock.")
	// FIX 13 (2026-06-06 dogfood): explicit per-file wall-clock cap so
	// a stuck model response (or a brutally slow model on a complex
	// file) doesn't pin the whole run. Default 3 min — see
	// scan.SastLocalDefaultPerFileTimeout for the rationale.
	analyzeCmd.Flags().DurationVar(&analyzeLocalLLMTimeout, "local-llm-per-file-timeout", 0,
		"per-file timeout for --local-llm calls (default 3m). Raise on slow models (deepseek-r1) or lower on faster ones.")
	analyzeCmd.Flags().BoolVar(&analyzeVerify, "verify", true,
		"after the secret scan, make one authenticated GET per distinct candidate key against the provider (OpenAI / Anthropic / xAI / GitHub / Stripe / Paystack) and record valid|invalid|unknown. Makes outbound calls, so it is auto-disabled under --local-llm (air-gap mode); also disable for air-gapped CI with --verify=false")
	analyzeCmd.Flags().BoolVar(&analyzeOnlyVerified, "only-verified", false,
		"hide secret findings whose verification returned `invalid`. Implies --verify. Does NOT silently drop unknown results — those still surface so a provider outage can't mask a real leak.")
	analyzeCmd.Flags().StringVar(&analyzeDiffRef, "diff-ref", "",
		"diff-scoped scan: only analyze files changed vs this git ref (e.g. origin/main, HEAD~1). The PR gate — fast, and the local-llm pass only spends on changed files.")
	analyzeCmd.Flags().StringVar(&analyzeDiffFile, "diff-file", "",
		"diff-scoped scan from a pre-generated unified diff file instead of --diff-ref (e.g. a CI artifact). Mutually exclusive with --diff-ref.")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	if analyzeWatch {
		return errors.New("--watch is not yet implemented (Phase 2)")
	}
	if _, ok := validFailOnLevels[analyzeFailOn]; !ok {
		return fmt.Errorf("--fail-on=%q is not one of: critical, high, medium, low, any, verified-critical, verified-high", analyzeFailOn)
	}

	// Local mode is an air-gap promise: --local-llm runs the whole pipeline
	// against a localhost Ollama and must make NO outbound calls. Secret
	// verification hits external provider whoami endpoints (api.openai.com,
	// api.stripe.com, …) and would ship the candidate key off the machine,
	// breaking that promise. So default verification OFF in local mode — unless
	// the user explicitly opted in via --verify or --only-verified.
	if analyzeLocalLLM && !cmd.Flags().Changed("verify") && !analyzeOnlyVerified {
		analyzeVerify = false
	}

	path := "."
	if len(args) == 1 {
		path = args[0]
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("stat %q: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", abs)
	}

	// Diff-scoped scan (--diff-ref / --diff-file): resolve the changed-file set
	// once, up front. Nil = full scan. We narrow the expensive local-llm pass to
	// these files (the cost win) and filter the final report to them — a PR gate
	// that only flags what the change touched.
	var changedFiles map[string]bool
	if analyzeDiffRef != "" || analyzeDiffFile != "" {
		changedFiles, err = gitdiff.ChangedSet(abs, analyzeDiffRef, analyzeDiffFile)
		if err != nil {
			return fmt.Errorf("--diff scope: %w", err)
		}
		if !analyzeQuiet {
			src := analyzeDiffRef
			if src == "" {
				src = analyzeDiffFile
			}
			fmt.Fprintf(cmd.ErrOrStderr(),
				"diff mode: %d changed file(s) vs %s — scanning only those\n", len(changedFiles), src)
		}
	}

	if !analyzeQuiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "getdebug %s — scanning %s\n", version, abs)
	}

	// Ignore rules: .gitignore (respected by default) + .getdebug-ignore
	// (always applied). Loaded once at the workdir root and shared by
	// all three scan passes — matches the hosted-scan behaviour, which
	// only sees committed files because it clones from the git remote.
	ignoreLog := func(format string, args ...any) {
		if !analyzeQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "  "+format+"\n", args...)
		}
	}
	rules := scan.LoadIgnoreRules(abs, !analyzeNoGitignore, !analyzeNoDefaultIgnores, ignoreLog)

	start := time.Now()
	res, err := scan.ScanSecrets(scan.ScanOptions{Workdir: abs, IgnoreRules: rules})
	if err != nil {
		// Truly fatal — partial walks never bubble here (the walker swallows
		// per-file errors), so reaching this branch means we couldn't open
		// the root or hit a real disk failure.
		return fmt.Errorf("scan: %w", err)
	}
	elapsed := time.Since(start)

	if !analyzeQuiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "scanned %d files in %s\n",
			res.ScannedFiles, elapsed.Round(time.Millisecond))
		// FIX 5 (2026-06-06 dogfood): actionable truncation hint.
		// Pre-fix message was "hit 20 MB total-bytes cap; rerun on a
		// smaller subset for full coverage" — accurate but vague. Now
		// the CLI names the file the walk stopped at AND points at the
		// existing `.getdebug-ignore` mechanism users can use to
		// exclude the heavy subtree. Multi-line so the actionable
		// part doesn't get lost when the user scrolls.
		if res.Truncated {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ hit 20 MB total-bytes cap")
			if res.TruncatedAt != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), " — walk stopped at %s\n", res.TruncatedAt)
			} else {
				fmt.Fprintln(cmd.ErrOrStderr())
			}
			fmt.Fprintln(cmd.ErrOrStderr(),
				"    add the heavy subtree to .getdebug-ignore (e.g. `bench/`, `fixtures/`) or rerun on a smaller path:")
			fmt.Fprintln(cmd.ErrOrStderr(),
				"      getdebug analyze ./src    # narrow the scope")
			fmt.Fprintln(cmd.ErrOrStderr(),
				"      echo 'bench/' >> .getdebug-ignore   # then re-run from the repo root")
		}
	}

	// AI-app regex prefilters — deterministic, no LLM call. Runs on every
	// analyze (free, no Ollama needed). Phase 1.7 Item 1b.
	aiStart := time.Now()
	aiRes, aiErr := scan.ScanAiAppRegex(abs, rules, func(format string, args ...any) {
		if !analyzeQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "  "+format+"\n", args...)
		}
	})
	if aiErr != nil {
		return fmt.Errorf("ai-app regex pass: %w", aiErr)
	}
	if !analyzeQuiet && aiRes.FilesConsidered > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"ai-app regex: scanned %d of %d JS/TS files in %s · %d findings\n",
			aiRes.FilesScanned, aiRes.FilesConsidered,
			time.Since(aiStart).Round(time.Millisecond),
			len(aiRes.Findings))
	}
	res.Findings = append(res.Findings, aiRes.Findings...)

	// Optional: local-LLM SAST pass via Ollama. Runs AFTER the secrets pass
	// so the regex findings always surface, even if Ollama is down or the
	// model errors. Findings from the model are merged into res.Findings.
	if analyzeLocalLLM {
		model := analyzeLocalLLMModel
		if model == "" {
			model = localllm.DefaultModel
		}
		client := localllm.New(os.Getenv("GETDEBUG_OLLAMA_URL"))
		if err := client.Ping(cmd.Context(), model); err != nil {
			return fmt.Errorf("--local-llm: %w", err)
		}
		if !analyzeQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "local-llm SAST: %s via Ollama …\n", model)
		}
		sastStart := time.Now()
		sastRes, sastErr := scan.ScanSastLocal(cmd.Context(), scan.SastLocalOptions{
			Workdir:        abs,
			Client:         client,
			Model:          model,
			MaxFiles:       analyzeLocalLLMMax,
			PerFileTimeout: analyzeLocalLLMTimeout,
			IgnoreRules:    rules,
			OnlyFiles:      changedFiles, // nil = full scan; diff mode = changed only

			Logf: func(format string, args ...any) {
				if !analyzeQuiet {
					fmt.Fprintf(cmd.ErrOrStderr(), "  "+format, args...)
				}
			},
		})
		if sastErr != nil {
			return fmt.Errorf("local-llm: %w", sastErr)
		}
		if !analyzeQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"local-llm: analyzed %d of %d in %s · %d malformed · %d errors\n",
				sastRes.FilesScanned, sastRes.FilesConsidered,
				time.Since(sastStart).Round(time.Second),
				sastRes.Malformed, sastRes.Errors)
			if sastRes.LlmCalls > 0 {
				// The local model runs on-device → $0 in real spend. Show the
				// tokens and what the same work would cost on a hosted model, so
				// the air-gap's value (free local AI) is explicit. Reference rate:
				// gemini-2.5-flash-lite list price ($0.10/M in, $0.40/M out) — an
				// informational estimate, not a bill.
				cloudUsd := float64(sastRes.PromptTokens)/1e6*0.10 + float64(sastRes.OutputTokens)/1e6*0.40
				fmt.Fprintf(cmd.ErrOrStderr(),
					"local-llm cost: %d tokens (%d in + %d out) over %d call(s) · $0.00 on-device (Ollama) · ≈ $%.4f on a hosted model\n",
					sastRes.PromptTokens+sastRes.OutputTokens, sastRes.PromptTokens, sastRes.OutputTokens,
					sastRes.LlmCalls, cloudUsd)
			}
		}
		res.Findings = append(res.Findings, sastRes.Findings...)
	}

	// Dedupe: when both the regex prefilter and the LLM SAST land on
	// the same (file, line, category) triple, the regex hit wins (it
	// has deterministic provenance + a tighter matched-span). Order-
	// preserving so the secrets pass + regex prefilter rows stay
	// first in the report — those are the highest-confidence findings.
	res.Findings = dedupeFindings(res.Findings)

	// Diff-scoped: keep only findings in changed files. The cheap passes
	// (secrets, ai-app regex) scanned the whole tree; this scopes the REPORT to
	// the change (the local-llm pass was already scoped at the walk). Done before
	// verification so we don't make outbound whoami calls for out-of-scope keys.
	if changedFiles != nil {
		res.Findings = filterToChangedFiles(res.Findings, changedFiles)
	}

	// Secret verification: --only-verified implies --verify; treating
	// either as on triggers the pass. We do it AFTER dedupe so the same
	// key in two collapsed findings only verifies once.
	if analyzeVerify || analyzeOnlyVerified {
		if !analyzeQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "verifying secret findings against provider whoami endpoints …\n")
		}
		res.Findings = scan.VerifyFindings(cmd.Context(), res.Findings, scan.VerifyOptions{})
		if analyzeOnlyVerified {
			res.Findings = filterOutInvalidSecrets(res.Findings)
		}
	}

	if analyzeSARIF != "" {
		if err := writeSARIFFile(analyzeSARIF, res.Findings); err != nil {
			return fmt.Errorf("write SARIF: %w", err)
		}
		if !analyzeQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote SARIF → %s\n", analyzeSARIF)
		}
	}

	if analyzeJSON {
		if err := writeNDJSON(cmd.OutOrStdout(), res.Findings); err != nil {
			return fmt.Errorf("write JSON: %w", err)
		}
	} else {
		report.WriteTable(cmd.OutOrStdout(), res.Findings)
	}

	if analyzeCI && countAtOrAbove(res.Findings, analyzeFailOn) > 0 {
		// Print a final banner to stderr so it's visible in CI logs even
		// when stdout is captured to a file.
		fmt.Fprintf(cmd.ErrOrStderr(),
			"\ngetdebug: %d finding(s) at or above --fail-on=%s — failing build.\n",
			countAtOrAbove(res.Findings, analyzeFailOn), analyzeFailOn)
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		return ErrCIThresholdExceeded
	}
	return nil
}

// dedupeFindings collapses findings that match on (filePath, lineStart,
// category) — the case where the LLM SAST pass surfaces the same shape
// the regex prefilter already caught. First occurrence wins, so the
// secrets pass + regex prefilter rows (which run first) shadow any
// later LLM duplicate. Order-preserving — the report's ranking stays
// stable.
// filterToChangedFiles keeps only findings whose file is in the diff-scoped
// changed set. Paths are compared in forward-slash form to match the set built
// by gitdiff. Order-preserving.
func filterToChangedFiles(in []scan.Finding, changed map[string]bool) []scan.Finding {
	out := make([]scan.Finding, 0, len(in))
	for _, f := range in {
		if changed[filepath.ToSlash(f.FilePath)] {
			out = append(out, f)
		}
	}
	return out
}

func dedupeFindings(in []scan.Finding) []scan.Finding {
	if len(in) <= 1 {
		return in
	}
	type key struct {
		filePath  string
		lineStart int
		category  string
	}
	seen := make(map[key]struct{}, len(in))
	out := in[:0]
	for _, f := range in {
		k := key{filePath: f.FilePath, lineStart: f.LineStart, category: f.Category}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}

// filterOutInvalidSecrets implements --only-verified: drop secret
// findings whose verification status is `invalid`. `unknown` and `valid`
// both surface — we never silently mask a real leak just because the
// provider was down. Non-secret findings pass through unchanged.
func filterOutInvalidSecrets(in []scan.Finding) []scan.Finding {
	out := in[:0]
	for _, f := range in {
		if f.Category == "secrets" && f.Verification != nil && f.Verification.Status == scan.VerificationInvalid {
			continue
		}
		out = append(out, f)
	}
	return out
}

// countAtOrAbove counts findings at or above the threshold for `--fail-on`.
// Lower severityRank = more severe, so we want findings whose rank <= the
// threshold's rank.
//
// FIX 15 (2026-06-06 dogfood): `verified-*` is an INCLUSION gate, not a
// subtraction. The previous logic only skipped secret findings whose
// status was explicitly `invalid` — so anything `unknown` (no provider
// configured, network blip, regex-only detector) still counted. On
// crewAI, `--fail-on=verified-high` and `--fail-on=high` produced the
// identical 28-finding fail. The high-precision lane disappeared.
//
// Inclusion semantics: a finding counts under `verified-*` only when its
// detector produced an affirmative verification signal. See
// affirmativelyVerified for the per-category rules.
func countAtOrAbove(fs []scan.Finding, level string) int {
	limit := thresholdRank(level)
	wantsVerified := level == "verified-critical" || level == "verified-high"
	n := 0
	for _, f := range fs {
		if report.SeverityRank(f.Severity) > limit {
			continue
		}
		if wantsVerified && !affirmativelyVerified(f) {
			continue
		}
		n++
	}
	return n
}

// affirmativelyVerified reports whether a finding carries positive
// evidence — provider 2xx for secrets today, with reachability + judge
// signals added as the workers-context pipeline lands in the CLI. A
// finding without an affirmative signal does NOT count under `verified-*`
// (that is the whole point of the lane). Use plain `high` / `critical`
// when you want the broad gate that includes unverified findings.
func affirmativelyVerified(f scan.Finding) bool {
	switch f.Category {
	case "secrets":
		// Provider returned 2xx for the key → real, live, leak-blast-radius
		// high. `unknown` (provider down, no verifier configured) and
		// `invalid` (regex matched but not a key shape) are NOT positive
		// signals — they're absence of disproof, which is exactly what
		// `verified-*` is designed to filter out.
		return f.Verification != nil && f.Verification.Status == scan.VerificationValid
	default:
		// dependency-cve reachability + SAST judge-pass live in the
		// workers-added context that the CLI does not yet read from
		// hosted analyze. Until that wiring lands, conservative: no
		// affirmative signal = no inclusion.
		return false
	}
}

func thresholdRank(level string) int {
	switch level {
	case "critical", "verified-critical":
		return report.SeverityRank(scan.SeverityCritical)
	case "high", "verified-high":
		return report.SeverityRank(scan.SeverityHigh)
	case "medium":
		return report.SeverityRank(scan.SeverityMedium)
	case "low":
		return report.SeverityRank(scan.SeverityLow)
	case "any":
		// Everything above `info` — Low is the lowest severity that a real
		// detector emits today.
		return report.SeverityRank(scan.SeverityLow)
	default:
		return report.SeverityRank(scan.SeverityHigh)
	}
}
