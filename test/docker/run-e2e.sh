#!/bin/sh
# run-e2e.sh — convenience wrapper that boots the compose stack, runs
# every script under tests/, and tears down. Intended for local
# iteration; CI invokes the same compose file directly so the GA log
# UI surfaces the agent container's stdout.
#
# Assumes ./clawpatrol is already built (make build) so the Dockerfile
# can COPY it in without a Go toolchain step. Errors out fast when the
# binary is missing.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${here}/../.." && pwd)"

if [ ! -x "${repo_root}/clawpatrol" ]; then
    echo "run-e2e.sh: ${repo_root}/clawpatrol missing — run 'make build' first" >&2
    exit 64
fi

cleanup() {
    cd "${here}"
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cd "${here}"

echo "==> building images"
docker compose build --quiet

echo "==> bringing up gateway + agent"
# --exit-code-from agent propagates the entrypoint's exit status, so
# `set -e` on the caller covers failure.
docker compose up \
    --abort-on-container-exit \
    --exit-code-from agent
