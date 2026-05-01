#!/bin/sh
# Claw Patrol installer.
#
# Usage:
#   curl -fsSL https://clawpatrol.dev/install.sh | sh
#
# Environment overrides:
#   CLAWPATROL_INSTALL_DIR  Target directory (default: $HOME/.local/bin)
#   CLAWPATROL_VERSION      Release tag like v0.0.41 (default: latest)
#
# Downloads the platform-appropriate binary from
# https://clawpatrol.dev/dl/<version>/clawpatrol-<triple>, installs it to
# $CLAWPATROL_INSTALL_DIR/clawpatrol, and prints `clawpatrol --version`.

set -eu

base_url="https://clawpatrol.dev"
version="${CLAWPATROL_VERSION:-latest}"
install_dir="${CLAWPATROL_INSTALL_DIR:-${HOME:-}/.local/bin}"

err() {
  printf 'clawpatrol install: %s\n' "$1" >&2
  exit 1
}

[ -n "$install_dir" ] || err "no install directory (set CLAWPATROL_INSTALL_DIR or HOME)"

# Resolve platform triple from uname.
os=$(uname -s 2>/dev/null || echo unknown)
arch=$(uname -m 2>/dev/null || echo unknown)

case "$os" in
  Linux)
    case "$arch" in
      x86_64|amd64) triple="linux-x64-gnu" ;;
      aarch64|arm64) triple="linux-arm64-gnu" ;;
      *) err "unsupported Linux architecture: $arch (supported: x86_64, aarch64)" ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      arm64|aarch64) triple="darwin-arm64" ;;
      x86_64)
        err "macOS x86_64 is not supported (only Apple Silicon / arm64 builds are published)"
        ;;
      *) err "unsupported macOS architecture: $arch (supported: arm64)" ;;
    esac
    ;;
  *)
    err "unsupported OS: $os (supported: Linux, Darwin)"
    ;;
esac

asset="clawpatrol-$triple"
url="$base_url/dl/$version/$asset"

command -v curl >/dev/null 2>&1 || err "curl is required"

tmp=$(mktemp 2>/dev/null) || err "failed to create temp file"
trap 'rm -f "$tmp"' EXIT INT HUP TERM

printf 'Downloading %s\n' "$url"
curl -fsSL --output "$tmp" "$url" \
  || err "download failed: $url"

# Sanity-check the download. --fail above already rejects 4xx/5xx;
# this guards against a zero-byte body slipping through.
[ -s "$tmp" ] || err "downloaded file is empty: $url"

mkdir -p "$install_dir" || err "failed to create $install_dir"
target="$install_dir/clawpatrol"
chmod +x "$tmp" || err "chmod failed on $tmp"
mv -f "$tmp" "$target" || err "failed to move binary into $target"
trap - EXIT INT HUP TERM

printf '\nInstalled %s\n' "$target"

# PATH advisory — print only, never edit shell rc files.
case ":${PATH:-}:" in
  *":$install_dir:"*) ;;
  *)
    printf '\nNote: %s is not on your PATH.\n' "$install_dir"
    printf 'Add it to your shell rc file with:\n'
    # shellcheck disable=SC2016 # printing literal $PATH for the user to paste
    printf '\n  export PATH="%s:$PATH"\n\n' "$install_dir"
    ;;
esac

# Confirm by invoking the binary by full path (independent of PATH).
printf '\n'
"$target" --version
