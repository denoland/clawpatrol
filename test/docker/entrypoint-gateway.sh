#!/bin/sh
# entrypoint-gateway.sh — runs `clawpatrol gateway` against the harness
# policy. Stays in the foreground so docker compose can health-probe
# the dashboard port; the tests/ sidecar waits on healthy before
# joining.

set -eu

CONFIG="${CLAWPATROL_CONFIG:-/opt/clawpatrol/gateway.hcl}"

if [ ! -r "$CONFIG" ]; then
    echo "entrypoint-gateway: cannot read $CONFIG" >&2
    exit 64
fi

mkdir -p /var/lib/clawpatrol

# `clawpatrol gateway` reads the path positionally.
if [ -n "${CP_E2E_DASHBOARD_PASSWORD:-}" ]; then
    exec /usr/local/bin/clawpatrol gateway \
        --set-dashboard-password "${CP_E2E_DASHBOARD_PASSWORD}" \
        "$CONFIG"
fi
exec /usr/local/bin/clawpatrol gateway "$CONFIG"
