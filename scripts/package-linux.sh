#!/usr/bin/env bash
# Build a local Linux release tarball (same layout as CI).
# Usage: ./scripts/package-linux.sh [target]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
TAG="v${VERSION}"
DIST="${ROOT}/dist"
mkdir -p "$DIST"

echo "==> cargo build -p oscar-cli --release --locked --target ${TARGET}"
rustup target add "$TARGET" 2>/dev/null || true
cargo build -p oscar-cli --release --locked --target "$TARGET"

BIN="${ROOT}/target/${TARGET}/release/oscar"
test -x "$BIN"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp "$BIN" "$STAGE/oscar"
cp README.md LICENSE CHANGELOG.md "$STAGE/" 2>/dev/null || true

VER_TAR="oscar-${TAG}-${TARGET}.tar.gz"
case "$TARGET" in
  x86_64-*)   STABLE="oscar-x86_64-unknown-linux-gnu.tar.gz" ;;
  aarch64-*)  STABLE="oscar-aarch64-unknown-linux-gnu.tar.gz" ;;
  *)          STABLE="oscar-${TARGET}.tar.gz" ;;
esac

tar -C "$STAGE" -czf "${DIST}/${VER_TAR}" oscar README.md LICENSE CHANGELOG.md 2>/dev/null \
  || tar -C "$STAGE" -czf "${DIST}/${VER_TAR}" oscar
cp "${DIST}/${VER_TAR}" "${DIST}/${STABLE}"
(cd "$DIST" && sha256sum "$VER_TAR" "$STABLE" | tee SHA256SUMS)

echo
echo "Artifacts in ${DIST}:"
ls -lh "${DIST}/${VER_TAR}" "${DIST}/${STABLE}" "${DIST}/SHA256SUMS"
echo
echo "Install: tar -xzf ${DIST}/${STABLE} && sudo install -m 755 oscar /usr/local/bin/oscar"
