#!/bin/sh
# clawpatrol installer. Downloads a prebuilt binary from GitHub Pages
# (https://denoland.github.io/clawpatrol) — source repo is private,
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

BASE="https://denoland.github.io/clawpatrol"
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

# source-build branch (private repo — needs gh auth)
if [ "${CLAWPATROL_FROM_SOURCE:-0}" = "1" ]; then
  REF="${CLAWPATROL_REF:-main}"
  command -v go  >/dev/null 2>&1 || fail "go toolchain required for source build"
  command -v git >/dev/null 2>&1 || fail "git required"
  SRC=$(mktemp -d)
  trap 'rm -rf "$SRC"' EXIT INT TERM
  say "cloning denoland/clawpatrol@${REF}"
  if command -v gh >/dev/null 2>&1; then
    gh repo clone denoland/clawpatrol "$SRC" -- --depth 1 --branch "$REF" >/dev/null 2>&1 \
      || gh repo clone denoland/clawpatrol "$SRC" -- --depth 1 >/dev/null 2>&1 \
      || fail "gh repo clone failed (run \`gh auth login\` first?)"
  else
    fail "private repo — install gh and run \`gh auth login\`, or unset CLAWPATROL_FROM_SOURCE to download a binary"
  fi
  if command -v deno >/dev/null 2>&1 && [ -d "$SRC/dashboard" ]; then
    say "building dashboard"
    ( cd "$SRC/dashboard" && deno install >/dev/null 2>&1 && deno task build >/dev/null 2>&1 ) \
      || say "dashboard build failed (skipping)"
  fi
  mkdir -p "$SRC/dashboard/dist"
  if [ -z "$(ls -A "$SRC/dashboard/dist" 2>/dev/null)" ]; then
    printf '<!doctype html><html><body><pre>dashboard not built</pre></body></html>' > "$SRC/dashboard/dist/index.html"
  fi
  say "building clawpatrol"
  ( cd "$SRC" && go build -ldflags "-s -w" -o clawpatrol ./cmd/clawpatrol ) || fail "go build failed"
  mv "$SRC/clawpatrol" "$PREFIX/clawpatrol"
  chmod +x "$PREFIX/clawpatrol"
  say "installed: $PREFIX/clawpatrol"
  exit 0
fi

# binary download (default)
URL="${BASE}/releases/${VERSION}/clawpatrol-${OS}-${ARCH}"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM
say "downloading ${URL}"
curl -fsSL -o "$TMP" "$URL" || fail "download failed (no release for ${OS}-${ARCH} at ${VERSION}?)"

# optional sha256 verify
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

# macOS: install Clawpatrol.app for `clawpatrol run`
# The .app holds the system extension that intercepts per-process
# flows. Without it `clawpatrol run` errors. Pulled from the same
# release as the Go binary, expanded to /Applications. Skip silently
# if the artifact isn't present (older releases or unsigned dev runs).
if [ "$OS" = "darwin" ]; then
  APP_URL="${BASE}/releases/${VERSION}/Clawpatrol.app.tar.gz"
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
