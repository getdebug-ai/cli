# Changelog

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
