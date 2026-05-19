#!/usr/bin/env node
// Post-install: download the right prebuilt getdebug binary for this host.
//
// The launcher in bin/getdebug.cjs is what npm exposes as `getdebug`. It
// execs the binary cached at bin/getdebug(.exe) next to this install script.
// Naming and download URL follow the convention used by goreleaser-style
// release pipelines:
//   getdebug_<version>_<platform>_<arch>.tar.gz       (unix)
//   getdebug_<version>_windows_<arch>.zip             (windows)
//
// Skip behavior:
//   - GETDEBUG_SKIP_DOWNLOAD=1 → no-op (useful for monorepo dev installs).
//   - GETDEBUG_BINARY=/abs/path → record it in bin/.bin-path and skip the
//     download. The launcher consults that file before falling back to the
//     bundled cache. Useful when this repo's own `go build` output is in use.

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const https = require("node:https");
const { spawnSync } = require("node:child_process");
const zlib = require("node:zlib");

const VERSION = require("./package.json").version;
const REPO = "getdebug-ai/cli";
const BIN_DIR = path.join(__dirname, "bin");

function platformTriple() {
  const platform = process.platform; // 'darwin' | 'linux' | 'win32'
  const arch = process.arch; // 'x64' | 'arm64' | …
  if (!["darwin", "linux", "win32"].includes(platform)) {
    return null;
  }
  if (!["x64", "arm64"].includes(arch)) {
    return null;
  }
  return { platform, arch };
}

function targetName({ platform, arch }) {
  // goreleaser convention: lowercase OS + arch, x86_64 for x64.
  const osPart = platform === "win32" ? "windows" : platform;
  const archPart = arch === "x64" ? "x86_64" : "arm64";
  const ext = platform === "win32" ? "zip" : "tar.gz";
  return {
    archiveName: `getdebug_${VERSION}_${osPart}_${archPart}.${ext}`,
    binaryName: platform === "win32" ? "getdebug.exe" : "getdebug",
  };
}

function downloadUrl(archiveName) {
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${archiveName}`;
}

function follow(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    function go(u, left) {
      https
        .get(u, (res) => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            if (left <= 0) return reject(new Error(`Too many redirects for ${url}`));
            res.resume();
            return go(new URL(res.headers.location, u).toString(), left - 1);
          }
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`HTTP ${res.statusCode} for ${u}`));
          }
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve(Buffer.concat(chunks)));
          res.on("error", reject);
        })
        .on("error", reject);
    }
    go(url, maxRedirects);
  });
}

function untarSingleBinary(tgz, binaryName) {
  // Minimal tar extractor: we only need to pull the one binary entry out.
  // Format: 512-byte header + (size, rounded to 512) payload. Name in
  // bytes [0,100). Type flag at [156]. '0' or '\0' = regular file.
  const tar = zlib.gunzipSync(tgz);
  let off = 0;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header[0] === 0) break; // end of archive (zero block)
    const rawName = header.subarray(0, 100).toString("utf8").replace(/\0+$/, "");
    const sizeOctal = header.subarray(124, 136).toString("utf8").replace(/\0+$/, "").trim();
    const size = sizeOctal ? Number.parseInt(sizeOctal, 8) : 0;
    const typeFlag = String.fromCharCode(header[156] || 48);
    const blocks = Math.ceil(size / 512);
    const payloadStart = off + 512;
    const payloadEnd = payloadStart + size;
    if (
      (typeFlag === "0" || typeFlag === "\0") &&
      path.basename(rawName) === binaryName
    ) {
      return tar.subarray(payloadStart, payloadEnd);
    }
    off = payloadStart + blocks * 512;
  }
  return null;
}

function unzipSingleBinary(zipBuf, binaryName) {
  // Minimal central-directory walk + per-entry deflate. ZIP entries we
  // emit via goreleaser are stored or deflated; both are handled here.
  // Find End of Central Directory record (signature 0x06054b50).
  const EOCD = 0x06054b50;
  let eocdOff = -1;
  for (let i = zipBuf.length - 22; i >= Math.max(0, zipBuf.length - 65557); i--) {
    if (zipBuf.readUInt32LE(i) === EOCD) {
      eocdOff = i;
      break;
    }
  }
  if (eocdOff < 0) return null;
  const totalEntries = zipBuf.readUInt16LE(eocdOff + 10);
  const cdOffset = zipBuf.readUInt32LE(eocdOff + 16);

  let off = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (zipBuf.readUInt32LE(off) !== 0x02014b50) break; // central dir header sig
    const compressedSize = zipBuf.readUInt32LE(off + 20);
    const fileNameLen = zipBuf.readUInt16LE(off + 28);
    const extraLen = zipBuf.readUInt16LE(off + 30);
    const commentLen = zipBuf.readUInt16LE(off + 32);
    const localHeaderOff = zipBuf.readUInt32LE(off + 42);
    const name = zipBuf
      .subarray(off + 46, off + 46 + fileNameLen)
      .toString("utf8");
    off += 46 + fileNameLen + extraLen + commentLen;
    if (path.basename(name) !== binaryName) continue;

    // Local file header: 30 bytes + filename + extra, then payload.
    const localFileNameLen = zipBuf.readUInt16LE(localHeaderOff + 26);
    const localExtraLen = zipBuf.readUInt16LE(localHeaderOff + 28);
    const method = zipBuf.readUInt16LE(localHeaderOff + 8);
    const payloadStart = localHeaderOff + 30 + localFileNameLen + localExtraLen;
    const payload = zipBuf.subarray(payloadStart, payloadStart + compressedSize);
    if (method === 0) return payload;
    if (method === 8) return zlib.inflateRawSync(payload);
    return null;
  }
  return null;
}

function recordBinPath(absPath) {
  fs.writeFileSync(path.join(BIN_DIR, ".bin-path"), absPath);
}

async function main() {
  if (process.env.GETDEBUG_SKIP_DOWNLOAD === "1") {
    console.log("[getdebug] GETDEBUG_SKIP_DOWNLOAD=1, skipping binary download");
    return;
  }
  if (process.env.GETDEBUG_BINARY && fs.existsSync(process.env.GETDEBUG_BINARY)) {
    recordBinPath(path.resolve(process.env.GETDEBUG_BINARY));
    console.log(`[getdebug] using GETDEBUG_BINARY=${process.env.GETDEBUG_BINARY}`);
    return;
  }

  const triple = platformTriple();
  if (!triple) {
    console.warn(
      `[getdebug] No prebuilt binary for ${process.platform}/${process.arch}. ` +
        "Set GETDEBUG_BINARY to a locally-built `getdebug` to use this package.",
    );
    return; // Fail soft: leave bin/.bin-path empty; launcher will print the same hint on first run.
  }

  const { archiveName, binaryName } = targetName(triple);
  const url = downloadUrl(archiveName);
  const outPath = path.join(BIN_DIR, binaryName);

  try {
    console.log(`[getdebug] downloading ${url}`);
    const buf = await follow(url);
    const binary = archiveName.endsWith(".zip")
      ? unzipSingleBinary(buf, binaryName)
      : untarSingleBinary(buf, binaryName);
    if (!binary) {
      throw new Error(`Archive ${archiveName} did not contain ${binaryName}`);
    }
    fs.writeFileSync(outPath, binary);
    fs.chmodSync(outPath, 0o755);
    recordBinPath(outPath);
    // Smoke: ensure the binary runs (`--version`). Failure isn't fatal — the
    // launcher will surface a clear error on the user's first invocation.
    const probe = spawnSync(outPath, ["--version"], { stdio: "ignore" });
    if (probe.status !== 0) {
      console.warn(`[getdebug] downloaded binary failed --version probe (exit ${probe.status})`);
    } else {
      console.log(`[getdebug] installed → ${outPath}`);
    }
  } catch (err) {
    // Fail soft: a postinstall crash blocks `npx`. The launcher will retry
    // (or print a clear error) when the user actually invokes `getdebug`.
    console.warn(`[getdebug] postinstall download failed: ${err.message}`);
    console.warn(
      "[getdebug] `getdebug` will try again on first invocation. " +
        "If that also fails, set GETDEBUG_BINARY to a locally-built binary.",
    );
  }
}

main();
