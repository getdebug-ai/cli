#!/usr/bin/env node
// Launcher: exec the prebuilt `getdebug` binary that postinstall (install.js)
// dropped into this same `bin/` directory. If postinstall failed (offline at
// install time, etc.) we try once more on first run and then give a clear
// error so the user knows what to do.

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const BIN_DIR = __dirname;
const BIN_PATH_FILE = path.join(BIN_DIR, ".bin-path");
const DEFAULT_BIN = path.join(BIN_DIR, process.platform === "win32" ? "getdebug.exe" : "getdebug");

function resolveBinary() {
  // GETDEBUG_BINARY env override wins — useful for dev / monorepo workflows
  // where the user is running their own `go build` output.
  if (process.env.GETDEBUG_BINARY && fs.existsSync(process.env.GETDEBUG_BINARY)) {
    return process.env.GETDEBUG_BINARY;
  }
  if (fs.existsSync(BIN_PATH_FILE)) {
    const recorded = fs.readFileSync(BIN_PATH_FILE, "utf8").trim();
    if (recorded && fs.existsSync(recorded)) return recorded;
  }
  if (fs.existsSync(DEFAULT_BIN)) return DEFAULT_BIN;
  return null;
}

function ensureBinaryOrRetry() {
  let bin = resolveBinary();
  if (bin) return bin;
  // Postinstall didn't land a binary. Try once more synchronously so the
  // user's `npx getdebug …` invocation doesn't fail just because their
  // install ran offline.
  try {
    require("../install.js");
  } catch {
    // install.js runs main() at top level; if it threw, fall through
    // to the diagnostic below.
  }
  return resolveBinary();
}

const binary = ensureBinaryOrRetry();
if (!binary) {
  process.stderr.write(
    [
      "getdebug: no prebuilt binary available for this platform.",
      `  platform=${process.platform} arch=${process.arch}`,
      "  Build from source and set GETDEBUG_BINARY:",
      "    git clone https://github.com/getdebug-ai/cli",
      "    cd getdebug/cli && go build -o getdebug ./cmd/getdebug",
      "    GETDEBUG_BINARY=$(pwd)/getdebug npx getdebug --help",
      "",
    ].join("\n"),
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  process.stderr.write(`getdebug: failed to exec ${binary}: ${result.error.message}\n`);
  process.exit(1);
}
process.exit(result.status ?? 1);
