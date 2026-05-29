#!/bin/sh
# 01-https-mitm.sh — sanity probe: agent dials the gateway's MITM-able
# HTTPS endpoint via `clawpatrol run` and the request lands in the
# gateway's action log.
#
# Currently a smoke check — the full assertion (gateway log line
# matches the agent's request) is wired up once entrypoint-agent.sh
# can curl the dashboard's /api/actions endpoint and parse the result.
# Until then, exit 0 if `clawpatrol run` exited cleanly.

set -eu

CLAWPATROL_BIN="${CLAWPATROL_BIN:-/usr/local/bin/clawpatrol}"

# echo.example.test is intercepted by the gateway's `https.echo`
# endpoint. resolving it requires the gateway to be on the DNS path —
# `clawpatrol run` puts us inside the agent netns where that's true.
"${CLAWPATROL_BIN}" run -- \
    curl --silent --max-time 5 \
         --resolve echo.example.test:443:127.0.0.1 \
         --insecure \
         https://echo.example.test/ >/dev/null

# TODO: query GATEWAY_URL/api/actions and assert the request shows up.
