#!/usr/bin/env bash
# Cross-compile the getdebug CLI for every platform the npm launcher knows
# about and package each as a goreleaser-style archive that install.js can
# extract. Run from the repo root:
#
#   scripts/build-cli-binaries.sh 0.1.0
#
# Outputs into dist/cli/:
#   getdebug_<version>_darwin_x86_64.tar.gz
#   getdebug_<version>_darwin_arm64.tar.gz
#   getdebug_<version>_linux_x86_64.tar.gz
#   getdebug_<version>_linux_arm64.tar.gz
#   getdebug_<version>_windows_x86_64.zip
#   getdebug_<version>_windows_arm64.zip
#
# Upload these to the v<version> GitHub release; install.js downloads them
# by name. Then `npm publish` npm/cli/.

set -euo pipefail

VERSION="${1:?usage: scripts/build-cli-binaries.sh <version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/cli"
LDFLAGS="-s -w -X github.com/getdebug-ai/cli/internal/cmd.version=$VERSION"

rm -rf "$OUT"
mkdir -p "$OUT"

build() {
  local goos="$1" goarch="$2" arch_label="$3" archive_ext="$4"
  local binary="getdebug"
  if [ "$goos" = "windows" ]; then binary="getdebug.exe"; fi

  local staging
  staging="$(mktemp -d)"
  echo "[build] $goos/$goarch → $staging/$binary"
  (
    cd "$ROOT"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
      go build -ldflags "$LDFLAGS" -o "$staging/$binary" ./cmd/getdebug
  )

  local archive="getdebug_${VERSION}_${goos}_${arch_label}.${archive_ext}"
  if [ "$archive_ext" = "tar.gz" ]; then
    tar -C "$staging" -czf "$OUT/$archive" "$binary"
  else
    (cd "$staging" && zip -q "$OUT/$archive" "$binary")
  fi
  rm -rf "$staging"
  echo "[build]   → $OUT/$archive"
}

build darwin  amd64 x86_64 tar.gz
build darwin  arm64 arm64  tar.gz
build linux   amd64 x86_64 tar.gz
build linux   arm64 arm64  tar.gz
build windows amd64 x86_64 zip
build windows arm64 arm64  zip

echo
echo "Done. Upload the contents of $OUT to https://github.com/getdebug-ai/cli/releases/tag/v$VERSION"
echo "Then publish the launcher:  (cd npm/cli && npm publish --access=public)"
