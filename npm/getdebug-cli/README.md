# getdebug-cli

AI-powered codebase analyzer and auto-fixer. Find bugs and security issues
before you ship — secrets, dependency CVEs, prompt injection, weak crypto,
and more. Auto-fix-safe categories ship a PR with the patch attached.

The package name on npm is `getdebug-cli` because the unscoped `getdebug`
name was already taken on the registry. Once installed, the binary it
exposes is plain `getdebug`.

## Quick start

```sh
# Run once, no install:
npx getdebug-cli analyze .

# Or install globally — the binary is `getdebug`:
npm i -g getdebug-cli
getdebug analyze .

# Gate your CI on critical + high findings:
npx getdebug-cli analyze . --ci --fail-on=high
```

## What this package is

This npm package is a thin launcher. On install it downloads the right
prebuilt `getdebug` binary for your platform from the
[GitHub releases page](https://github.com/onfafanutifafa/getdebug/releases)
and execs it when you call `getdebug …`. The binary itself is a Go program
(in [`cli/`](https://github.com/onfafanutifafa/getdebug/tree/main/cli) in
the repo) — no Go toolchain required on your machine.

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
