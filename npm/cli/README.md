# @getdebug/cli

Security testing for AI apps — and everything else — before you ship. One
`getdebug analyze .` scans for committed secrets and the vulnerabilities
specific to LLM / agent apps (prompt injection, unsafe tool output, leaked
model keys, PII in prompts, and more), fully offline. The hosted platform
adds LLM-driven SAST, reachable-CVE dependency scanning, and one-click fix PRs.

Published under the `@getdebug` npm scope; source lives at
[github.com/getdebug-ai/cli](https://github.com/getdebug-ai/cli). The
short scope name on npm is intentional — your `package.json` and CI
commands stay clean. Once installed, the binary it exposes is `getdebug`.

## Quick start

```sh
# Run once, no install:
npx @getdebug/cli analyze .

# Or install globally — the binary is `getdebug`:
npm i -g @getdebug/cli
getdebug analyze .

# Gate your CI on critical + high findings:
npx @getdebug/cli analyze . --ci --fail-on=high
```

## AI-app security testing — the differentiator

Runs locally on every `analyze` — no LLM call, no account — across JS/TS
(incl. JSX, Svelte), Python, Go, and Ruby:

| Category | Catches | CWE · OWASP |
| --- | --- | --- |
| `prompt-injection` | Untrusted input interpolated into a prompt | CWE-77 · A03 |
| `unsafe-role-merge` | Caller-controlled text in the system/role channel | CWE-1039/863 · A04/A01 |
| `client-side-llm-key` | Model key exposed to the client or in a response | CWE-200 · A01 |
| `unsafe-tool-output` | Agent/tool output reaching a shell or SQL sink | CWE-78/89 · A03 |
| `pii-in-prompt` | DB rows / user objects / PII serialized into a prompt | CWE-359 · A04 |
| `unbounded-stream` | Streaming handler with no timeout / disconnect guard | CWE-400/770 · A04 |

Detectors are heuristic (regex prefilters) and gated — they only fire in
files that import an LLM SDK, so non-AI code stays silent.

## Verify before you alert (new in 0.5.0)

Regex matches keys by *shape* — every `sk_…` or `ghp_…` string in a
fixture or rotated config trips a critical. `--verify` (on by
default) makes one read-only request per distinct candidate against
the provider's whoami endpoint and records whether the key is
actually live, so the noisy ones step out of your CI gate without
silently disappearing from the report.

```sh
# Default — every secret finding gets a verification badge:
getdebug analyze .

# Hide the rejected-by-provider rows (unknown still surfaces — a
# provider outage must never silently mask a real leak):
getdebug analyze . --only-verified

# Strictest CI gate: only provider-verified LIVE secrets fail:
getdebug analyze . --ci --fail-on=verified-high

# Air-gapped CI? Skip the outbound call entirely:
getdebug analyze . --verify=false
```

Providers covered today: OpenAI, Anthropic, xAI, GitHub PAT
(classic + fine-grained), Stripe, Paystack, GitLab, npm, SendGrid,
Slack. Each verifier is one GET (or POST for Slack's
`auth.test`), 5s timeout, 5 req/s per-provider, identical keys
deduped per run.

## What this package is

This npm package is a thin launcher. On install it downloads the right
prebuilt `getdebug` binary for your platform from the
[GitHub releases page](https://github.com/getdebug-ai/cli/releases)
and execs it when you call `getdebug …`. The binary itself is a Go program
([source](https://github.com/getdebug-ai/cli)) — no Go toolchain required
on your machine.

## Supported platforms

| OS | Arch |
| --- | --- |
| macOS | x86\_64, arm64 |
| Linux | x86\_64, arm64 |
| Windows | x86\_64, arm64 |

## Environment variables

- `GETDEBUG_BINARY=/abs/path` — bypass the bundled binary and use the one at
  this path. Useful for monorepo dev workflows where you're running your own
  `go build` output.
- `GETDEBUG_SKIP_DOWNLOAD=1` — skip the postinstall download entirely. Pair
  with `GETDEBUG_BINARY` in CI sandboxes that can't reach GitHub releases.

## License

MIT
