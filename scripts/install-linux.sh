#!/usr/bin/env bash
# Install oscar CLI from GitHub Releases (Linux).
#
#   curl -fsSL https://raw.githubusercontent.com/JacksonJRay/oscar/main/scripts/install-linux.sh | bash
#   curl -fsSL ... | bash -s -- --version v0.1.0 --dir ~/.local/bin
#
set -euo pipefail

REPO="${OSCAR_REPO:-JacksonJRay/oscar}"
VERSION="${OSCAR_VERSION:-latest}"
INSTALL_DIR="${OSCAR_INSTALL_DIR:-}"
PREFIX_HINT=""

usage() {
  cat <<EOF
Install oscar from GitHub Releases (Linux gnu).

Options:
  --version TAG   Release tag (default: latest). Example: v0.1.0
  --dir DIR       Install directory (default: ~/.local/bin or /usr/local/bin if writable)
  --repo OWNER/R  GitHub repo (default: JacksonJRay/oscar)
  -h, --help      Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  TARGET_STABLE="oscar-x86_64-unknown-linux-gnu.tar.gz" ;;
  aarch64|arm64) TARGET_STABLE="oscar-aarch64-unknown-linux-gnu.tar.gz" ;;
  *)
    echo "unsupported arch: $arch (need x86_64 or aarch64)" >&2
    exit 1
    ;;
esac

if [[ -z "$INSTALL_DIR" ]]; then
  if [[ -w /usr/local/bin ]] || [[ "$(id -u)" -eq 0 ]]; then
    INSTALL_DIR=/usr/local/bin
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi
mkdir -p "$INSTALL_DIR"

if [[ "$VERSION" == "latest" ]]; then
  URL="https://github.com/${REPO}/releases/latest/download/${TARGET_STABLE}"
else
  # Prefer stable name on versioned release too; fallback to versioned tarball
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARGET_STABLE}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TARBALL="${TMP}/oscar.tar.gz"

echo "==> downloading ${URL}"
if ! curl -fL --retry 3 -o "$TARBALL" "$URL"; then
  if [[ "$VERSION" != "latest" ]]; then
    VER_URL="https://github.com/${REPO}/releases/download/${VERSION}/oscar-${VERSION}-${TARGET_STABLE#oscar-}"
    # oscar-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
    ARCH_PART="${TARGET_STABLE#oscar-}"
    VER_URL="https://github.com/${REPO}/releases/download/${VERSION}/oscar-${VERSION}-${ARCH_PART}"
    echo "==> retry ${VER_URL}"
    curl -fL --retry 3 -o "$TARBALL" "$VER_URL"
  else
    exit 1
  fi
fi

echo "==> extracting"
tar -xzf "$TARBALL" -C "$TMP"
if [[ ! -f "$TMP/oscar" ]]; then
  # tarball might nest — find binary
  BIN_PATH="$(find "$TMP" -type f -name oscar | head -1)"
else
  BIN_PATH="$TMP/oscar"
fi
chmod +x "$BIN_PATH"

DEST="${INSTALL_DIR}/oscar"
echo "==> install ${DEST}"
if [[ -w "$INSTALL_DIR" ]]; then
  install -m 755 "$BIN_PATH" "$DEST"
else
  sudo install -m 755 "$BIN_PATH" "$DEST"
fi

echo
"$DEST" --version || true
echo "Installed: $DEST"
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "Note: add ${INSTALL_DIR} to PATH, e.g. export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
