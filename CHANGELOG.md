# Changelog

## 0.5.9 — 2026-06-14

Two precision/correctness fixes ahead of the Phase 1.8 §3 outreach pass.
No new detectors — both tighten existing behaviour so the product does in
code what the docs claim.

### Fixed

- **`--local-llm` now defaults `--verify` off (air-gap honoured in code,
  not just copy).** Local mode runs the whole pipeline against a localhost
  Ollama and promises zero outbound calls, but the secret scanner still
  made authenticated whoami calls to provider endpoints (`api.openai.com`,
  `api.stripe.com`, …) — shipping the candidate key off the machine and
  breaking the air-gap promise. Verification now defaults OFF under
  `--local-llm` unless the user explicitly opts in with `--verify` or
  `--only-verified`. (`internal/cmd/analyze.go`)

- **CrewAI URM detectors gated on a CrewAI import.** The 0.5.6
  unrestricted-message-role detectors (`backstory=` / `goal=` / `role=`
  patterns) fired on any `role=<var>` kwarg in general Python — `role=None`,
  `role=getattr(msg, "role")` — producing 4 false positives on simonw/llm,
  which uses no CrewAI. All three CrewAI detectors now require a
  case-insensitive `crewai` marker in the file. Separately,
  `scanPyDynamicRole` now skips attribute-access role values
  (`{"role": message.role}`, `{"role": self.role}`) — those read the message
  object's own controlled role field, not a request-supplied variable.
  simonw/llm: 14 → 7 findings; it is now the regression fixture.
  (`internal/scan/aiapp_regex_py.go`)

## 0.5.8 — 2026-06-12

Cross-language AI-app detector waves from the CodeSecBench Tier C
calibration arc (cycles 4–7, bench builds 0.5.5 → 0.5.8). Eight
app-shaped public targets across four languages drove the detector
work; the corpus and its labels are public at
[getdebug-ai/codesecbench-truth](https://github.com/getdebug-ai/codesecbench-truth)
and written up at [codesecbench.org](https://codesecbench.org).

### Added

- **Python FastAPI / async wave (0.5.5).** Nine detectors in
  `aiapp_regex_py.go`: streaming handlers with no disconnect/cleanup
  guard (function-scoped, comment/docstring-stripped), httpx stream
  without timeout, `subprocess(shell=True)` / `os.system` tool sinks,
  f-string SQL, dynamic message role, persona-file system injection,
  key-in-response, RAG `.join` concat, and full-DB-row-into-prompt.
- **CrewAI agent wave (0.5.6).** Three detectors reaching the `Agent()`
  constructor surface: interpolated `backstory`/`goal`, backstory loaded
  from a file, and a request-derived `role=` kwarg (allowlist-suppressed).
- **Go AI-app path (0.5.7).** New `aiapp_regex_go.go` + `.go` dispatch,
  gated on an LLM-SDK marker so non-AI Go (including this CLI) stays
  silent. Twelve detectors across all six categories — fmt.Sprintf /
  strings.Join prompts, `anthropic.F(System:)`, openai-go `Role:`,
  os/exec, json.Marshal(user), `NewStreaming(context.Background())`.
- **Ruby on Rails path (0.5.8).** New `aiapp_regex_rb.go` + `.rb`
  dispatch, gated on a case-insensitive LLM-SDK marker. Fourteen
  detectors — `#{}` interpolation, `role: params[:role]`, backtick
  exec, `File.read("...#{}")`, `user.to_json`, `ActionController::Live`,
  `OpenAI::Client.new` without `request_timeout`.

### Notes

- All new detectors are extension-gated; existing JS/TS/Python behaviour
  is unchanged (verified zero-regression across the corpus). Result:
  corpus recall ~48% → 76%, with 100% precision on every target.
- The four early JS/TS targets (#1–#4) carry the residual FN tail; a
  future pass widens their point labels to spans.

## 0.5.1 — 2026-06-07

The Phase 1.8 §2 self-dogfood pass — 17 fixes catalogued from a
1,217-file Python run (crewAIInc/crewAI) and a full MCP round-trip
against the `debug` org itself, shipped before the §3 outreach
arc. Two of the three P0s collapse the false-positive rate on
real-world Python repos; the third makes `--fail-on=verified-*`
into the high-precision lane it always claimed to be.

### Changed

- **`--fail-on=verified-*` is now an inclusion gate.** Previously
  the only `verified-*`-specific behaviour was skipping
  `status=invalid` secrets, so `verified-high` matched plain
  `high` on every real repo — the precision lane was inert. A
  finding now counts under `verified-*` only when the detector
  produced an affirmative signal (provider 2xx for secrets;
  reachability + judge-pass land as the workers-context
  pipeline reaches the CLI). On crewAI: `verified-high` drops
  from blocking 28 to blocking 0 (no live secrets), matching
  the user expectation.
- **TTY output surfaces verifier badges.** Per-row
  `[LIVE]` / `[REJECTED]` / `[UNVERIFIED]` next to the severity
  badge, plus a bottom-of-output `Verification: N LIVE · N
  REJECTED · N UNVERIFIED` summary line. Same vocabulary as the
  hosted MCP. Empty when no findings carry verification data, so
  plain `analyze .` (no `--verify`) stays uncluttered.
- **Anthropic precedes OpenAI in the secrets regex table.**
  Anthropic tokens (`sk-ant-…`) now classify as Anthropic instead
  of being double-tagged as OpenAI and verifier-rejected with
  HTTP 401 from openai.com. The scan loop additionally tracks
  per-line consumed character ranges so one token can produce
  only one finding.
- **Default behaviour of `getdebug undo`:** the
  `.getdebug-backup-<TS>/` directory is removed after a
  successful restore. Pass `--keep-backup` to retain it for an
  audit trail or diff.
- **20 MB truncation hint** is multi-line + actionable.
  Surfaces the path the walk stopped at and points at
  `.getdebug-ignore` + a narrow-scope re-run instead of the old
  one-liner.

### Added

- **Detector regexes for xAI (`xai-`), GitLab (`glpat-`),
  npm (`npm_`)** — verifiers shipped in 0.5.0 but no detector,
  so real keys from those providers were silently missed.
- **`--local-llm-per-file-timeout`** — explicit per-file cap
  (default 3 min) on Ollama chat calls during the local SAST
  pass. Pre-fix ceiling was the localllm HTTP client's 10 min,
  so one stuck file could pin a whole run.
- **`--keep-backup`** on `getdebug undo` (see Changed above).
- **Progress meter on `--local-llm`** — per-file
  `[N/M] path · elapsed Ns · ETA Ns` log line so a 12+ min
  qwen-1.5b run doesn't leave the user wondering whether it's
  hung.

### Fixed

- **`message` and `query` removed from the Python prompt-injection
  identifier set.** Was firing on every `self.message = f"…"` in
  custom Exception subclasses + every `query = "SELECT …" + …`
  SQL builder. 14 of 22 HIGH false positives on crewAI came from
  this single pair.
- **`streamTruePyRe` requires kwarg context.** Now matches
  `(stream=True` and `,stream=True` only — kills FPs on
  `self.stream = True` attribute assignments + bare `stream = True`
  variable bindings. 9 medium FPs on crewAI.
- **PEM-block detector respects Python docstrings + doctest
  lines.** A `-----BEGIN PRIVATE KEY-----` marker inside a `"""…"""`
  triple-quote or on a `>>> …` doctest line no longer surfaces.
  Narrow — non-PEM patterns still fire in docstrings (a real
  `sk-…` accidentally pasted into a docstring is still a leak).
- **Placeholder regex covers fake/mock/stub-prefixed values.**
  crewAI's `.env.test` had 5 critical FPs on `fake-password` /
  `mock_key` / `stub-token`-shaped values.
- **Local-SAST file selection is ranked by security-relevance**
  before the MaxFiles cap. Pre-fix WalkDir gave alphabetical
  order, so the cap burned on `__init__.py` + constants before
  reaching auth/sql handlers. Heuristic keyword score + stable
  sort.
- **Localhost API URLs in `~/.getdebug/config.json` are no longer
  sticky** as the default for `getdebug login`. The fallback now
  skips a localhost pin and reverts to the prod default; users
  no longer have to `rm ~/.getdebug/config.json` after dev
  testing. `GETDEBUG_API_URL` still wins for explicit intent.
- **`getdebug fix . --local-only`** accepts `.` (and `./`,
  `./.`). Every other command treated `.` as the workdir alias;
  rejecting it only here was a paper cut.

### MCP

- **`GET /v1/findings/:id` exists.** The `get_finding` MCP tool
  was calling a route that didn't exist, so every list→drill
  flow died on the second step. The handler accepts the new
  stable id, the legacy `finding_<runId>_<hash>` form, and a
  bare content hash; falls back to content-hash latest-row when
  exact match misses. Returns 404 (not 403) on cross-org so the
  route isn't a probing oracle.
- **Stable finding ids on the wire.** The DB id rotated every
  scan (append-only `findings` table); `list_fixes` references
  went stale on the next scan and any cached agent id 404'd.
  All list / detail / run / architectural routes now surface
  `finding_<projectId>_<contentHash>` — same for the embedded
  finding ref in `list_fixes`. Legacy ids still resolve on the
  input side for backwards compat. MCP server code unchanged —
  same npm artifact, just gets stable ids now.

## 0.5.0 — 2026-06-06

The 700-FP cleanup — three additions that move getdebug's default
output from "wall of noise" to "ready to action" on real customer
repos. On the debug repo itself: **770 → 67 findings (-91%)**;
`--fail-on=high` CI gate goes from blocking ~756 to blocking 12.
On `directus/directus` as a customer-shape control: 45 dep-CVE
findings → `--fail-on=high` drops from blocking 5 to blocking 1
(the one direct-and-actionable CVE).

### Added

- **Import-level dep-CVE reachability** — `npm audit` /
  `pnpm audit` / `pip-audit` / `osv-scanner` flag every transitive
  package in the lockfile; we now record whether your source
  actually imports the affected package. Transitive-only findings
  are demoted one severity step (never dropped) so they step out
  of the gate without disappearing from the report. JS/TS,
  Python, Go covered.
  - New `--fail-on=reachable-critical` / `reachable-high`
    thresholds skip transitive-only dep-CVEs at the gate.
- **Secret verification (`--verify`, on by default)** — after
  the regex pass, getdebug makes one read-only request per
  distinct candidate against the provider's whoami endpoint
  and records `valid` / `invalid` / `unknown` on the finding.
  10 providers covered today: **OpenAI, Anthropic, xAI, GitHub PAT
  (classic + fine-grained), Stripe, Paystack, GitLab, npm,
  SendGrid, Slack**. 5s timeout, 5 req/s per-provider rate limit,
  identical keys deduped per run. AWS / GCP / Azure deferred —
  SigV4 + JWT signing is a separate hardening project.
  - New `--only-verified` flag — drops `invalid` from the report.
    `unknown` always still surfaces; a provider outage can't
    silently mask a real leak.
  - New `--fail-on=verified-critical` / `verified-high`
    thresholds — the tightest gate available, requires both
    reachable AND verified.

### Changed

- **Ignore-rule parity sweep** — the hosted scanner now applies
  the same `BuiltInIgnorePatterns()` matrix the CLI does, plus
  three new groups that close the noisiest gaps:
  - Local-dev env overrides (`.env.local`, `.env.<env>.local`).
    `.env` / `.env.production` still scan — a committed real key
    there remains a real leak.
  - Scanner output / bundled fixture data (`bench/results/*.json`,
    `bench-fixtures.json`, `coverage/`, `.gstack/`,
    `.vulnhuntr_checkpoint/`, `.nyc_output/`).
  - Test scaffolding (the existing CLI list, now also applied
    hosted-side).
- **HuggingFace tokens in markdown** join the doc-suppression
  list (Rule B extension) — bench's `METHODOLOGY.md` was
  flagging the labelled-corpus hf\_… strings as fresh leaks.
- **Local-only DB-URL placeholder check** — `user:user@localhost`
  and RFC-1918 / `127.0.0.1` hosts no longer trigger a "Database
  URL with inline credentials" critical. The repeated-credential
  signal alone is never a real prod cred; combined with localhost
  it's conclusive.
- **Removed duplicated `Hugging Face token` regex** — second
  pattern with 30+-char matching produced a duplicate finding on
  every real `hf_…` token. Kept the conservative 34+ form.

### Fixed

- **`go.sum` joins the lockfile skip list** — `h1:` / `h2:`
  content-address hashes were tripping the entropy pass on
  Go monorepos. CLI had it; the hosted secret scanner was
  missing it.

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
