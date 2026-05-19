# getdebug

AI-powered codebase analyzer and auto-fixer. Find security issues and bugs
before you ship — secrets, dependency CVEs, prompt injection, weak crypto,
and more. Auto-fix-safe categories ship a PR with the patch attached.

```sh
# Run once, no install — the CI gate that fails on critical findings:
npx @getdebug/cli analyze . --ci --fail-on=critical

# Or install globally:
npm i -g @getdebug/cli
getdebug analyze .
```

## What this repo is

This repo is the **CLI surface** of getdebug — a Go binary that runs a local
secrets scan + (eventually) drives uploads to the hosted analysis platform.
The platform side (web dashboard, API, LLM-app detectors, fix worker) is not
open source; this CLI is.

Source layout:

```
cmd/getdebug/        # main.go entrypoint
internal/cmd/        # cobra commands (analyze, fix, status, login, undo)
internal/scan/       # local detectors — secrets regex + Shannon entropy
internal/report/     # output formatters — terminal table + SARIF 2.1.0
internal/api/        # API client (for hosted-mode uploads, not yet wired)
internal/config/     # ~/.getdebug/config.json
npm/cli/             # @getdebug/cli npm launcher (the npx surface)
scripts/             # build-cli-binaries.sh — cross-compile for release
```

## What's in v0.1.0

The launch slice — what works **today, offline, with no account**:

- `getdebug analyze .` walks the directory and runs the local secrets
  detector (regex + Shannon entropy near credential keywords). Catches
  the highest-severity launch blockers: AWS / GitHub / Stripe / OpenAI /
  Anthropic keys, JWTs, private key blocks, high-entropy values near
  credential keywords.
- `--ci --fail-on={critical|high|medium|low|any}` — exit non-zero when
  findings meet the threshold. The CI gate the product promises.
- `--sarif=<path>` — write a SARIF 2.1.0 log for GitHub Code Scanning to
  ingest directly.
- `--json` — NDJSON output for downstream tooling.

Not in v0.1.0: `login`, `fix`, `status`, `undo` (stubs — these require
hosted API integration, coming next). Cross-file SAST, dependency CVE
checks, and the LLM-app prompt-injection detector live on the hosted side
and are surfaced via the dashboard at [getdebug.ai](https://getdebug.ai).

## Install

```sh
npx @getdebug/cli analyze .                 # one-shot
npm i -g @getdebug/cli && getdebug analyze . # global install
```

The npm package is a thin launcher that downloads the right prebuilt Go
binary for your platform on install. Supported: macOS / Linux / Windows ×
x86_64 / arm64.

## Building from source

```sh
go build -o getdebug ./cmd/getdebug
./getdebug analyze /path/to/repo
```

To produce all six release archives locally:

```sh
scripts/build-cli-binaries.sh 0.1.0
# → dist/cli/getdebug_0.1.0_{darwin,linux,windows}_{x86_64,arm64}.{tar.gz,zip}
```

## CI usage

GitHub Actions:

```yaml
- name: getdebug security gate
  run: npx @getdebug/cli analyze . --ci --fail-on=high --sarif=results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Any CI runner that has Node 18+ available will work the same way.

## Contributing

PRs welcome for new detector patterns (especially provider-specific secret
regexes), output format improvements, and platform support. For the hosted
platform side (web dashboard, API, fix worker), contributions are by invite
only — open an issue if you'd like to collaborate.

## License

[MIT](LICENSE).
