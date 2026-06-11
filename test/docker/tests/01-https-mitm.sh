#!/bin/sh
# 01-https-mitm.sh — sanity probe: agent dials the gateway's MITM-able
# HTTPS endpoint via `clawpatrol run` and the request lands in the
# gateway's action log.
#
# Regression target from divybot#184: after the relay supervisor died,
# long-running Docker agents lost gateway-mediated network access and
# started logging `error connecting to api.github.com`.

set -eu

out="$(timeout 30s "${CLAWPATROL_BIN}" run -- \
    curl -fsS https://api.github.com/rate_limit 2>&1)"

printf '%s' "$out" | grep -q '"rate"' || {
    printf '%s\n' "$out" >&2
    echo "api.github.com request did not return the GitHub rate payload" >&2
    exit 1
}
