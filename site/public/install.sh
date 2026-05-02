#!/bin/sh
# clawpatrol installer. Downloads a prebuilt binary from GitHub Pages
# (https://denoland.github.io/clawpatrol-go) — source repo is private,
# release artifacts are public via GH Pages. Falls back to source build
# when CLAWPATROL_FROM_SOURCE=1 (requires `gh auth login` for the
# private clone).
#
# Usage:
#   curl -fsSL https://clawpatrol.dev/install.sh | sh
#
# Options (env vars):
#   CLAWPATROL_VERSION       — release tag (default: latest)
#   CLAWPATROL_PREFIX        — install dir (default: $HOME/.local/bin)
#   CLAWPATROL_FROM_SOURCE   — 1 to build from source (gh CLI + Go required)
#   CLAWPATROL_REF           — git ref when building from source (default: main)
#
# POSIX sh.

set -eu

BASE="https://denoland.github.io/clawpatrol-go"
VERSION="${CLAWPATROL_VERSION:-latest}"
PREFIX="${CLAWPATROL_PREFIX:-$HOME/.local/bin}"

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

# --- source-build branch (private repo — needs gh auth) -------------
if [ "${CLAWPATROL_FROM_SOURCE:-0}" = "1" ]; then
  REF="${CLAWPATROL_REF:-main}"
  command -v go  >/dev/null 2>&1 || fail "go toolchain required for source build"
  command -v git >/dev/null 2>&1 || fail "git required"
  SRC=$(mktemp -d)
  trap 'rm -rf "$SRC"' EXIT INT TERM
  say "cloning denoland/clawpatrol-go@${REF}"
  if command -v gh >/dev/null 2>&1; then
    gh repo clone denoland/clawpatrol-go "$SRC" -- --depth 1 --branch "$REF" >/dev/null 2>&1 \
      || gh repo clone denoland/clawpatrol-go "$SRC" -- --depth 1 >/dev/null 2>&1 \
      || fail "gh repo clone failed (run \`gh auth login\` first?)"
  else
    fail "private repo — install gh and run \`gh auth login\`, or unset CLAWPATROL_FROM_SOURCE to download a binary"
  fi
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

# --- binary download (default) --------------------------------------
URL="${BASE}/releases/${VERSION}/clawpatrol-${OS}-${ARCH}"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM
say "downloading ${URL}"
curl -fsSL -o "$TMP" "$URL" || fail "download failed (no release for ${OS}-${ARCH} at ${VERSION}?)"

# --- optional sha256 verify -----------------------------------------
SUMS=$(curl -fsSL "${BASE}/releases/${VERSION}/SHA256SUMS" 2>/dev/null || true)
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
echo "next: clawpatrol join --url <gateway-url>"
