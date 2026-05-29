#!/bin/sh
# entrypoint-agent.sh — joins the gateway, then walks the test scripts
# mounted under /workspace/tests. Each script is invoked with
# CLAWPATROL_BIN=/usr/local/bin/clawpatrol and GATEWAY_URL in the
# environment; non-zero exit propagates as the agent container's exit
# code, which docker compose's `up --exit-code-from agent` translates
# into the harness's overall PASS/FAIL.

set -eu

GATEWAY="${GATEWAY_URL:-http://gateway:8080}"
TESTS_DIR="${1:-/workspace/tests}"

echo "[e2e-agent] joining ${GATEWAY}"
# Gateway URL is positional; --profile picks the gateway-side profile
# block (matches policy.hcl `profile "e2e" {}`). --no-trust skips the
# host-trust step because that needs sudo + a system trust store, both
# beyond what the harness container needs to assert on. --hostname pins
# the container's device-row identity so the assertions later can
# look the agent up by name.
#
# Join is best-effort while the harness is being filled in — the
# device-flow approval step still needs operator interaction, which the
# probe scripts mock for now. A failure here logs but doesn't abort so
# the placeholder tests still get their chance to assert.
if ! /usr/local/bin/clawpatrol join \
    --profile e2e \
    --no-trust \
    --hostname "e2e-agent" \
    "${GATEWAY}" 2>&1 | sed 's/^/[join] /'
then
    echo "[e2e-agent] WARNING: clawpatrol join failed; tests that depend on the tunnel will skip" >&2
fi

if [ ! -d "${TESTS_DIR}" ]; then
    echo "[e2e-agent] no tests dir at ${TESTS_DIR}; nothing to do" >&2
    exit 0
fi

PASS=0
FAIL=0
FAILED_NAMES=""
for t in "${TESTS_DIR}"/*.sh; do
    [ -r "$t" ] || continue
    name="$(basename "$t")"
    echo "[e2e-agent] ▶ ${name}"
    if CLAWPATROL_BIN=/usr/local/bin/clawpatrol \
        GATEWAY_URL="${GATEWAY}" \
        sh "$t"; then
        echo "[e2e-agent]   ✓ ${name}"
        PASS=$((PASS + 1))
    else
        rc=$?
        echo "[e2e-agent]   ✗ ${name} (exit ${rc})" >&2
        FAIL=$((FAIL + 1))
        FAILED_NAMES="${FAILED_NAMES} ${name}"
    fi
done

echo "[e2e-agent] summary: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
    echo "[e2e-agent] failed:${FAILED_NAMES}" >&2
    exit 1
fi
