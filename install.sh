#!/bin/sh
# clawpatrol installer. Downloads a prebuilt binary from GitHub Releases.
# Falls back to source build when CLAWPATROL_FROM_SOURCE=1 (requires Go).
#
# Usage:
#   curl -fsSL https://clawpatrol.dev/install.sh | sh
#
# Options (env vars):
#   CLAWPATROL_VERSION       — release tag (default: latest)
#   CLAWPATROL_PREFIX        — install dir (default: $HOME/.local/bin)
#   CLAWPATROL_FROM_SOURCE   — 1 to build from source (Go required)
#   CLAWPATROL_REF           — git ref when building from source (default: main)
#
# POSIX sh.

set -eu

REPO="denoland/clawpatrol"
VERSION="${CLAWPATROL_VERSION:-latest}"
PREFIX="${CLAWPATROL_PREFIX:-$HOME/.local/bin}"

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/${REPO}/releases/latest/download"
else
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) fail "unsupported arch: $ARCH" ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) fail "unsupported OS: $OS" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl required"
mkdir -p "$PREFIX"

# source-build branch
if [ "${CLAWPATROL_FROM_SOURCE:-0}" = "1" ]; then
  REF="${CLAWPATROL_REF:-main}"
  command -v go  >/dev/null 2>&1 || fail "go toolchain required for source build"
  command -v git >/dev/null 2>&1 || fail "git required"
  SRC=$(mktemp -d)
  trap 'rm -rf "$SRC"' EXIT INT TERM
  say "cloning ${REPO}@${REF}"
  git clone --depth 1 --branch "$REF" "https://github.com/${REPO}.git" "$SRC" >/dev/null 2>&1 \
    || git clone --depth 1 "https://github.com/${REPO}.git" "$SRC" >/dev/null 2>&1 \
    || fail "git clone failed"
  if command -v npm >/dev/null 2>&1 && [ -d "$SRC/www" ]; then
    say "building dashboard"
    ( cd "$SRC/www" && npm ci --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1 ) \
      || say "dashboard build failed (skipping)"
  fi
  mkdir -p "$SRC/www/dist"
  if [ -z "$(ls -A "$SRC/www/dist" 2>/dev/null)" ]; then
    printf '<!doctype html><html><body><pre>dashboard not built</pre></body></html>' > "$SRC/www/dist/index.html"
  fi
  say "building clawpatrol"
  ( cd "$SRC" && go build -ldflags "-s -w" -o clawpatrol . ) || fail "go build failed"
  mv "$SRC/clawpatrol" "$PREFIX/clawpatrol"
  chmod +x "$PREFIX/clawpatrol"
  say "installed: $PREFIX/clawpatrol"
  exit 0
fi

# binary download (default)
URL="${BASE}/clawpatrol-${OS}-${ARCH}"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM
say "downloading ${URL}"
curl -fsSL -o "$TMP" "$URL" || fail "download failed (no release for ${OS}-${ARCH} at ${VERSION}?)"

# optional sha256 verify
SUMS=$(curl -fsSL "${BASE}/SHA256SUMS" 2>/dev/null || true)
if [ -n "$SUMS" ]; then
  EXPECTED=$(printf '%s\n' "$SUMS" | awk -v f="clawpatrol-${OS}-${ARCH}" '$2==f{print $1}')
  if [ -n "$EXPECTED" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
      ACTUAL=$(shasum -a 256 "$TMP" | awk '{print $1}')
    else
      ACTUAL=""
    fi
    if [ -n "$ACTUAL" ]; then
      [ "$EXPECTED" = "$ACTUAL" ] || fail "sha256 mismatch (expected $EXPECTED, got $ACTUAL)"
      say "sha256 ok"
    fi
  fi
fi

mv "$TMP" "$PREFIX/clawpatrol"
chmod +x "$PREFIX/clawpatrol"
say "installed: $PREFIX/clawpatrol"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) printf '\n  add to PATH:  export PATH="%s:$PATH"\n\n' "$PREFIX" ;;
esac

"$PREFIX/clawpatrol" version 2>/dev/null || true
echo

# macOS: install Clawpatrol.app for `clawpatrol run`
# The .app holds the system extension that intercepts per-process
# flows. Without it `clawpatrol run` errors. Pulled from the same
# release as the Go binary, expanded to /Applications. Skip silently
# if the artifact isn't present (older releases or unsigned dev runs).
if [ "$OS" = "darwin" ]; then
  APP_URL="${BASE}/Clawpatrol.app.tar.gz"
  APP_TMP=$(mktemp -d)
  if curl -fsSL -o "$APP_TMP/app.tgz" "$APP_URL" 2>/dev/null; then
    say "installing Clawpatrol.app to /Applications"
    rm -rf /Applications/Clawpatrol.app 2>/dev/null \
      || sudo rm -rf /Applications/Clawpatrol.app 2>/dev/null \
      || fail "couldn't remove old /Applications/Clawpatrol.app (need sudo?)"
    if ! tar -xzf "$APP_TMP/app.tgz" -C /Applications 2>/dev/null; then
      sudo tar -xzf "$APP_TMP/app.tgz" -C /Applications \
        || fail "extract Clawpatrol.app failed"
    fi
  else
    say "Clawpatrol.app not in this release; skipping (run \`clawpatrol run\` won't work on macOS until you install the .app)"
  fi
  rm -rf "$APP_TMP"
fi

echo "next: clawpatrol join <gateway-url>"
