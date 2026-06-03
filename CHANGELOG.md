# Changelog

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
  hosted side and are surfaced via [getdebug.ai](https://getdebug.ai)).
- Running `getdebug analyze .` on this repo returns 0 findings — test
  fixtures use string-concatenation (`"AKIA" + "IOSFODNN7EXAMPLE"`) so
  contiguous token shapes never appear in source. Same trick keeps
  GitHub Secret Scanning's push protection from flagging the repo.
  A `.getdebug-ignore` mechanism for downstream config is on the roadmap.
