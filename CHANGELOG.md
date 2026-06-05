# Changelog

## 0.4.0 — 2026-06-05

Two substantial additions: **Python AI-app regex prefilters** (same
five categories as the JS/TS set) and **default-ignore patterns**
for common test scaffolding (so the first scan on a real codebase is
signal-rich, not noise-rich). Plus a real product-bug fix in the
unbounded-stream prefilter that comments could falsely satisfy.

### Added
- **Python AI-app regex prefilters** — five categories now fire on
  `.py` files: `pii-in-prompt`, `unsafe-role-merge`,
  `prompt-injection`, `unbounded-stream`, `unsafe-tool-output`.
  Skipped `client-side-llm-key` for Python because the public-prefix
  bundle-leak vector (NEXT_PUBLIC_ / VITE_) doesn't have a Python
  equivalent. Patterns target the conventional shapes:
  `{"role": "system", "content": f"...{var}..."}`, `stream=True`,
  `subprocess.run(tool_call.input.cmd, shell=True)`, etc.
- **Default ignore patterns** — every `getdebug analyze` now skips
  test scaffolding by default: `**/*.test.*`, `**/*.spec.*`,
  `**/*_test.go`, `**/test_*.py`, `**/*_test.py`, `**/__tests__/**`,
  `**/__fixtures__/**`, `**/__snapshots__/**`, `**/__mocks__/**`,
  `**/testdata/**`. Conservative — only patterns that are
  unambiguously test-scaffolding (no `bench/`, no `fixtures/`,
  nothing single-word ambiguous). Override with
  `--no-default-ignores`.
- **`go.sum` added to the generated-lockfile skip list** —
  alongside `package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`,
  etc. Go's lockfile is full of `h1:` dependency hashes that look
  like high-entropy secrets to the regex pass; it never contains
  real credentials.

### Changed
- **The unbounded-stream prefilter now strips Python comments from
  the context window before checking for bound-stream markers.** A
  comment like `# TODO: add timeout near streaming call` was wrongly
  satisfying the "stream is bounded" check, silently suppressing
  real findings. Caught during calibration; would have been a real
  end-user FP.

### Bench (https://www.getdebug.dev/bench)

Python AI-app comparison (10 paired vulnerable/safe fixtures, three
tools):

```
Tool        TP  FP  FN   Precision  Recall
getdebug     5   0   0    100%       100%
bandit       1   1   4    50%        20%
semgrep      1   1   4    50%        20%
```

Bandit + Semgrep catch the generic `subprocess.run(shell=True)`
shape but fire on the SAFE allowlist-then-run variant too, and miss
the four behavioural AI-app categories entirely (pii-in-prompt,
unsafe-role-merge, prompt-injection, unbounded-stream).

Real-world signal/noise on `simonw/llm` (48 .py files):

```
Tool        Total findings    Signal
bandit      1,189            1,158 are assert_used (pytest); 0 AI-app
semgrep     3                3 generic-SAST hits; 0 AI-app
getdebug    6                6 AI-app findings
```

vulnhuntr (Protect AI's LLM-driven AI-app specialist, the stated
category leader) had multiple 2026-stack reliability issues that
prevented a clean run — full notes in the release blog post.

## 0.3.0 — 2026-06-04

Closes the local-vs-hosted parity gap that made dogfooding `analyze .`
on a working codebase produce noisy results — gitignored files
(scan-result caches, .env.local, tooling artifacts) were being walked
even though the hosted scan correctly never sees them. Also lands 4
more AI-app regex prefilter categories, taking default-scan recall
from 25% to 75% on the published bench corpus.

### Added
- **`.gitignore` respected by default**, including nested `.gitignore`
  files anywhere under the workdir. Each `.gitignore`'s rules are
  scoped to its directory (matches git's own semantics), so a
  `results/` rule inside `bench/.gitignore` only excludes paths under
  `bench/`. On the getdebug repo this drops a 549-finding self-scan
  down to 65 — closing the gap with the hosted scan's 95 (the
  remaining delta is the LLM SAST pass that's hosted-only).
- **`.getdebug-ignore`** — a scanner-specific overlay using standard
  gitignore syntax. Always applied (the `--no-gitignore` flag below
  doesn't disable it), so it's the right place for "skip this tracked
  file" (e.g. `**/*.test.ts`) or "re-include this gitignored file"
  (with a `!pattern` line).
- **4 new AI-app regex prefilter categories** on every default scan
  (no Ollama needed):
    - `pii-in-prompt` (CWE-359, high) — `JSON.stringify(<user-shape>)`
      where the variable name is in a curated allowlist
      (user/profile/account/...) AND an LLM-call marker is within ±20
      lines. Skips locally-built reduction vars like `safeContext`.
    - `unsafe-role-merge` (CWE-1039, high) — `role: "system"` message
      whose content is a template literal with `${}` interpolation.
      Object-scoped lookahead via a brace-tracking helper so a static
      system role followed by an interpolated user role doesn't
      falsely fire.
    - `prompt-injection` (CWE-77, high) — a variable named prompt /
      fullPrompt / systemPrompt / etc. assigned a literal + identifier
      concatenation. Multi-line via `(?s)`. Ignores constant
      `SYSTEM_PROMPT` assignments and unrelated path-style concat.
    - `unsafe-tool-output` (CWE-78, critical) — exec/spawn/run/eval
      sink called with a tool-output reference as its arg
      (`tool.input.*`, `block.input.*`, `toolUse.input.*`, etc.). The
      allowlist-then-run safe pattern stays clean because the sink
      arg is a static const.
- **`--no-gitignore` flag** on `analyze` for the rare case someone
  wants to scan everything on disk regardless of gitignore rules.
  `.getdebug-ignore` still applies in this mode.

### Changed
- **String-literal-aware comment skip in the AI-app regex pass**:
  matches inside test-description strings like
  `it("flags role: 'system' ...", ...)` no longer fire. Walks back
  through the line counting unescaped quote toggles.

### Bench corpus (published at https://www.getdebug.dev/bench)

```
                  TP  FP  FN  Precision  Recall
getdebug          6   5   2   0.55       0.75   ← was 0.55 / 0.25 on v0.2.0
gitleaks          2   1   6   0.67       0.25
trufflehog        0   0   8   0          0
```

The 3× recall improvement comes entirely from the 4 new regex
prefilters; precision is unchanged. Note: gitleaks + trufflehog are
secret-scanners and don't claim coverage on AI-app behavioral
categories — included as the secret-shape baseline only.

## 0.2.0 — 2026-06-03

Phase 1.7 — closes the WEDGE positioning gaps with three substantial
additions: a deterministic AI-app regex prefilter pass that runs on
every analyze (no Ollama required), an end-to-end local fix engine
that applies the same patcher set the hosted side uses, and a
suppression → prompt-context loop that feeds team-accepted patterns
back into the local LLM SAST prompt.

### Added
- **AI-app regex prefilters on `getdebug analyze`** — two new
  deterministic detector categories that run alongside the secrets
  pass on every scan, with no LLM call:
    - `client-side-llm-key` (CWE-798, critical) — catches LLM
      provider keys leaked through `NEXT_PUBLIC_*`, `VITE_*`,
      `EXPO_PUBLIC_*`, `REACT_APP_*`, `PUBLIC_*` env vars. Provider
      list is narrow + capitalised (OpenAI / Anthropic / Claude /
      Gemini / Google AI / xAI / Grok / Cohere / Mistral / Perplexity
      / DeepSeek / Groq / Replicate / HuggingFace / Together /
      Fireworks / Ollama) so loose word matches like "AI" don't
      over-fire.
    - `unbounded-stream` (CWE-770, medium) — catches `stream: true`
      on LLM calls with no `AbortController` / `signal:` / `.abort()`
      in the surrounding ±40 lines. Filters `TextDecoder.decode({
      stream: true })` false-positives.
  Both run before the LLM SAST pass; when `--local-llm` is also
  used, dedupe by `(file, line, category)` keeps the regex hit (tight
  matched-span + deterministic provenance) over the LLM duplicate.
- **`getdebug fix --local-only` — end-to-end on-laptop fix engine**
  with the same 8 pure-function patchers the hosted side ships:
  `weak-crypto`, `insecure-random`, `xss`, `insecure-cors`,
  `open-redirect`, `client-side-llm-key`, `unbounded-stream`,
  `dependency-cve`. No HTTP, no auth, no remote dependency. Detects
  the 4 high-signal patterns (weak-crypto / insecure-random / xss /
  insecure-cors) directly by regex; the other 4 are accessible via
  the patcher API for future `--findings <path>` integration.
  Backups land at `.getdebug-backup-<UTC-ts>/` before any write;
  original file mode bits preserved. `--apply` writes, omitting
  `--apply` is a dry-run preview.
- **`getdebug analyze --local-llm` AI-app detector catalog
  expansion** — the local Ollama SAST pass now covers the same 6
  AI-app risk classes the hosted holistic pass does:
  prompt-injection, unsafe-tool-output, pii-in-prompt,
  unsafe-role-merge, client-side-llm-key, unbounded-stream. System
  prompt rewritten holistic-style so small local models (qwen2.5-
  coder:7b, deepseek-r1:7b) get the same calibration the hosted
  model receives.
- **Suppression → prompt-context loop** on the local LLM SAST pass.
  `.getdebug/suppressions.json` in the workdir feeds team-accepted
  patterns into the local model's system prompt as first-party
  policy (separate prompt section from the trust-boundary block).
  The model is instructed to flag NEW variants rather than blindly
  suppress the category. Per-pattern + category-wide suppressions
  supported; hash-only suppressions stay out of the prompt (still
  filter at write-time on the hosted side).

### Security
- Trust-boundary markers (`<<<CODE_START>>>` / `<<<CODE_END>>>`)
  wrap every file the local LLM SAST pass sees. System prompt
  explicitly instructs the model to never follow instructions inside
  the markers and to flag injection attempts as `prompt-injection`
  findings. Mirrors the hosted defense — without it, a malicious file
  could have made the scanner report empty findings on attacker code.
- Severity floor enforcement on every local SAST finding. Each
  category carries a `defaultSeverity`; the floor is enforced on
  every reported finding (model can raise above it but never below).
  Defends against both confused-small-model misclassification and
  prompt-injection attempts that downgrade `critical` → `info` to
  slip past `--fail-on=critical` CI gates.

### Tests
- 100+ new Go tests across `internal/scan/` and `internal/fix/`,
  covering every new patcher (drift safety, multiple-hits-per-line
  decline, language-specific shapes), the regex prefilter precision
  guards (comment skip, quote-leading skip, TextDecoder skip,
  AbortController-in-scope skip, provider-list narrowness), the
  fix engine end-to-end (round-trip apply with backup, dry-run
  doesn't write, vendor-dir skip, file-mode preservation), and the
  suppression loader (missing file silent, malformed JSON logged,
  normalisation, reason cap, item cap, splice point above the
  trust boundary).

## 0.1.1 — 2026-05-29

Catches the published CLI up to the current product. The 0.1.0 binary
predated local mode and several fixes; 0.1.1 ships the real thing.

### Added
- `getdebug login` — real RFC 8628 device flow (was a stub in 0.1.0).
- `getdebug status` / `getdebug fix` / `getdebug undo` — real
  implementations (apply patches with reversible backups).
- `getdebug index --local` / `getdebug search --local` — on-device code
  intelligence via Ollama. Your code never leaves your machine.

### Changed
- Default API base URL is now `https://api.getdebug.dev` (was a `.ai`
  host that no longer resolves). Override with `--api` / `GETDEBUG_API_URL`.

### Security
- `fix --apply` validates patch paths — a malicious diff can no longer
  traverse outside the repo root.
- `--api` rejects non-https URLs (loopback excepted) so device-flow
  tokens can't be exchanged in cleartext.
- `--local` index skips symlinks; config file refuses to load with
  group/other-readable permissions; SARIF output path is validated.

## 0.1.0 — 2026-05-19

First public release of the getdebug CLI.

### Added
- `getdebug analyze [path]` — local two-pass secrets detector (provider
  regex + Shannon entropy near credential keywords). Covers AWS, Google,
  GitHub PATs (classic + fine-grained), Stripe, Paystack, Slack, OpenAI,
  Anthropic, JWTs, SendGrid, Heroku (with context-word requirement), and
  private-key blocks.
- `--ci --fail-on={critical|high|medium|low|any}` — CI gate with proper
  exit codes for build pipelines.
- `--sarif=<path>` — SARIF 2.1.0 output, ready for GitHub Code Scanning
  (`upload-sarif` action).
- `--json` — NDJSON output for downstream tooling.
- `--quiet` — suppress the scan-progress banner.
- `@getdebug/cli` npm launcher — `npx @getdebug/cli analyze .` works on
  macOS, Linux, and Windows (x86_64 and arm64).

### Known limitations
- `login`, `fix`, `status`, `undo` commands are stubs (require hosted API
  integration — coming next).
- No cross-file SAST or dependency CVE scanning yet (those live on the
  hosted side and are surfaced via [getdebug.dev](https://getdebug.dev)).
- Running `getdebug analyze .` on this repo returns 0 findings — test
  fixtures use string-concatenation (`"AKIA" + "IOSFODNN7EXAMPLE"`) so
  contiguous token shapes never appear in source. Same trick keeps
  GitHub Secret Scanning's push protection from flagging the repo.
  A `.getdebug-ignore` mechanism for downstream config is on the roadmap.
