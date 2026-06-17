# getdebug

**Security testing for AI apps — and everything else — before you ship.**

A single `getdebug analyze .` scans your codebase for committed secrets and the
security mistakes that are specific to LLM / agent applications — prompt
injection, untrusted tool output reaching shells and SQL, leaked model keys,
PII in prompts, and more. Connect the hosted platform and you also get full
LLM-driven SAST, reachable-CVE dependency scanning, and one-click fix PRs.

## Quick start

```sh
# Install — pick one:
npm i -g @getdebug/cli                 # global → the `getdebug` command
brew install getdebug-ai/tap/getdebug  # homebrew tap
npx @getdebug/cli analyze .            # …or run with zero install, no account

# Scan the current repo — offline, no account, fully local:
getdebug analyze .

# CI gate that fails the build on critical/high findings:
getdebug analyze . --ci --fail-on=high --sarif=results.sarif
```

No Go toolchain needed — the npm package and Homebrew formula both pull a
prebuilt binary for your platform. Requires Node 18+ (for the npm / npx path).

## What makes it different — AI-app security testing

Most scanners were built for traditional web apps and are blind to how an
LLM / agent app actually gets owned. getdebug ships a dedicated detector family
for these, and it runs **locally, on every `analyze`, with no LLM call and no
account**:

| Category | What it catches | CWE · OWASP |
| --- | --- | --- |
| `prompt-injection` | Untrusted input interpolated straight into a prompt | CWE-77 · A03 |
| `unsafe-role-merge` | Caller/request-controlled text merged into the system/role channel | CWE-1039/863 · A04/A01 |
| `client-side-llm-key` | An LLM provider key exposed to the client or returned in a response | CWE-200 · A01 |
| `unsafe-tool-output` | Agent / tool output flowing into a shell or SQL sink | CWE-78/89 · A03 |
| `pii-in-prompt` | DB rows, user objects, or PII serialized into a prompt | CWE-359 · A04 |
| `unbounded-stream` | A streaming handler with no timeout or disconnect guard | CWE-400/770 · A04 |

The detectors are heuristic (regex prefilters), deterministic, and **gated** —
they only fire in files that actually look like AI apps (an LLM-SDK import
marker is present), so a non-AI codebase stays silent. Languages covered:
**JavaScript / TypeScript** (incl. JSX and Svelte), **Python**, **Go**, **Ruby**.

## What runs where

| | `analyze .` (offline, no account) | `--local-llm` (Ollama) | Hosted (free account) |
| --- | :---: | :---: | :---: |
| Secrets (regex + entropy) | ✅ | ✅ | ✅ |
| AI-app security (6 categories) | ✅ | ✅ | ✅ |
| Live-key verification (`--verify`) | ✅ | off (air-gap) | ✅ |
| SAST — sql-i, cmd-i, xss, ssrf, weak-crypto, … | — | ✅ local model | ✅ cloud model |
| Dependency CVEs + reachability | — | — | ✅ |
| Auto-fix as a pull request | — | — | ✅ |

`--local-llm` runs the LLM SAST pass against a local Ollama model, so your code
never leaves the machine — and `--verify` auto-disables under it, leaving zero
outbound calls (a true air-gap). The hosted platform (dashboard, fix worker,
dependency scanning, MCP server) lives at [getdebug.dev](https://getdebug.dev)
and is not open source; **this CLI is**.

## Verify secrets before you alert

Regex matches keys by *shape* — every `sk_…` or `ghp_…` in a fixture or rotated
config trips a critical. `--verify` (on by default) makes one read-only whoami
request per distinct candidate and records whether the key is actually **live**,
so the noisy ones step out of your CI gate without silently disappearing from
the report.

```sh
getdebug analyze .                                # each secret gets a live / rejected / unknown badge
getdebug analyze . --only-verified                # hide provider-rejected rows (unknown still shows)
getdebug analyze . --ci --fail-on=verified-high   # gate only on LIVE secrets
getdebug analyze . --verify=false                 # air-gapped CI: skip the outbound call
```

Providers covered: OpenAI, Anthropic, xAI, GitHub (classic + fine-grained),
Stripe, Paystack, GitLab, npm, SendGrid, Slack.

## Install

Three ways, all shown in [Quick start](#quick-start) above:

- **npm** — `npm i -g @getdebug/cli` installs the `getdebug` command globally.
- **Homebrew** — `brew install getdebug-ai/tap/getdebug`.
- **npx** — `npx @getdebug/cli …` runs with zero install, no account.

The npm package is a thin launcher that downloads the right prebuilt Go binary
for your platform on install — no Go toolchain required. Supported: macOS /
Linux / Windows × x86\_64 / arm64.

## CI usage

```yaml
- name: getdebug security gate
  run: npx @getdebug/cli analyze . --ci --fail-on=high --sarif=results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`--sarif=<path>` writes SARIF 2.1.0 for GitHub Code Scanning to ingest; `--json`
emits NDJSON for downstream tooling. Any CI runner with Node 18+ works.

On pull requests, scope the gate to the diff so it only flags what the PR
touched (and the local-model pass only spends on changed files):

```yaml
- run: npx @getdebug/cli analyze . --ci --fail-on=high --diff-ref origin/${{ github.base_ref }}
```

Untracked-but-new files only appear in `--diff-ref` once committed (it diffs
git refs); a pre-generated diff works too via `--diff-file <path>`.

## Scan only what changed (diff mode)

For a pull-request gate, scope the scan to the diff. It's faster, and the
local-model SAST pass only spends on changed files instead of the whole repo.

```sh
getdebug analyze . --diff-ref origin/main      # files changed vs a branch/ref
getdebug analyze . --diff-ref HEAD~1           # …or vs the previous commit
getdebug analyze . --diff-file pr.diff         # …or from a pre-generated diff
```

By default diff mode scans exactly the changed files (depth 0). Add
`--diff-depth N` to also scan the **callers** of changed files — so a change to
a shared module re-checks the handlers that depend on it:

```sh
getdebug analyze . --diff-ref origin/main --diff-depth 1   # changed files + direct importers
```

Caller resolution covers **JS/TS** (relative imports), **Python** (relative +
package imports), **Go** (package imports, via `go.mod`), and **Ruby**
(`require_relative`). Imports it can't resolve (e.g. a bare Ruby `require`, or
Go without a `go.mod`) simply don't expand — those files still scan at depth 0.
Notes:

- Untracked new files only appear once committed (`--diff-ref` diffs git refs).
- `--diff-ref` and `--diff-file` are mutually exclusive.

## Cost visibility

`getdebug` is honest about what AI analysis costs. The `--local-llm` pass runs
on-device (Ollama), so it costs **nothing** — but it still reports the tokens it
used and what the same work would have cost on a hosted model:

```
local-llm: analyzed 12 of 12 in 2m3s · 0 malformed · 0 errors
local-llm cost: 18,402 tokens (15,1k in + 3,3k out) over 12 call(s) · $0.00 on-device (Ollama) · ≈ $0.0028 on a hosted model
```

For hosted scans, each run's estimated AI spend shows up in `getdebug status`
(the `AI COST` column) and on the dashboard; a run that hit its server-side
budget ceiling is flagged so a partial scan never looks clean. All cost figures
are list-price estimates, not a bill — reconcile real spend with your provider.

## Commands

- `getdebug analyze [path]` — the scan described above. Offline by default; add
  `--local-llm` for the local-model SAST pass. Add `--diff-ref <ref>` (or
  `--diff-file <path>`) to scan only files changed vs a git ref — the fast PR
  gate, and the local-llm pass only spends on what changed. Add `--diff-depth 1`
  to also scan the callers of changed files (resolves JS/TS + Python imports;
  Go/Ruby stay at the changed files only).
- `getdebug login` — connect to the hosted platform (OAuth 2.0 device flow,
  RFC 8628).
- `getdebug fix <id> [--apply]` — preview (default) or apply a generated patch;
  applied fixes are backed up to `.getdebug-backup-<timestamp>/`.
- `getdebug index` / `getdebug search` — local semantic code index + search via
  Ollama; the code never leaves your machine.
- `getdebug status` / `getdebug undo` — run status, and revert applied local fixes.

## Source layout

```
cmd/getdebug/    # main.go entrypoint
internal/cmd/    # cobra commands (analyze, fix, login, status, index, search, undo)
internal/scan/   # local detectors — secrets, ai-app (6 categories × 4 languages),
                 #   local-LLM SAST, live-key verification, ignore rules
internal/report/ # output formatters — terminal table + SARIF 2.1.0 + JSON
internal/api/    # hosted API client (login, uploads)
internal/config/ # ~/.getdebug/config.json
npm/cli/         # @getdebug/cli npm launcher (the npx surface)
scripts/         # build-cli-binaries.sh — cross-compile for release
```

## Building from source

```sh
go build -o getdebug ./cmd/getdebug
./getdebug analyze /path/to/repo

# produce all six release archives locally:
scripts/build-cli-binaries.sh <version>
# → dist/cli/getdebug_<version>_{darwin,linux,windows}_{x86_64,arm64}.{tar.gz,zip}
```

## Contributing

PRs welcome for new detector patterns — especially AI-app shapes for frameworks
we don't cover yet, and provider-specific secret regexes — plus output-format
and platform-support improvements. The hosted platform side (web dashboard, API,
fix worker) is contribution-by-invite; open an issue if you'd like to collaborate.

## License

[MIT](LICENSE).
