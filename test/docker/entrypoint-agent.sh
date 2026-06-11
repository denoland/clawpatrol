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
E2E_HOME=/home/e2e
COOKIE=/tmp/clawpatrol-e2e-cookie
PASSWORD="${CP_E2E_DASHBOARD_PASSWORD:-clawpatrol-e2e-password}"

json_get() {
    jq -r "$1 // empty"
}

echo "[e2e-agent] bootstrapping WireGuard client state from ${GATEWAY}"
mkdir -p "${E2E_HOME}/.clawpatrol" "${E2E_HOME}/.config/clawpatrol"

curl -fsS -c "${COOKIE}" \
    -d "password=${PASSWORD}" \
    "${GATEWAY}/__login" >/tmp/e2e-login.html

curl -fsS "${GATEWAY}/ca.crt" -o "${E2E_HOME}/.clawpatrol/ca.crt"

start_json="$(curl -fsS -X POST \
    "${GATEWAY}/api/onboard/start?hostname=e2e-agent&profile=e2e")"
device_code="$(printf '%s' "$start_json" | json_get '.device_code')"
user_code="$(printf '%s' "$start_json" | json_get '.user_code')"
if [ -z "$device_code" ] || [ -z "$user_code" ]; then
    echo "[e2e-agent] onboard/start returned unusable payload: ${start_json}" >&2
    exit 1
fi

curl -fsS -b "${COOKIE}" -X POST \
    "${GATEWAY}/api/onboard/approve?code=${user_code}&profile=e2e" >/tmp/e2e-approve.json

auth_key=""
api_token=""
for _ in $(seq 1 30); do
    poll_json="$(curl -fsS -X POST "${GATEWAY}/api/onboard/poll?device_code=${device_code}")"
    auth_key="$(printf '%s' "$poll_json" | json_get '.auth_key')"
    api_token="$(printf '%s' "$poll_json" | json_get '.api_token')"
    [ -n "$auth_key" ] && break
    sleep 1
done
if [ -z "$auth_key" ]; then
    echo "[e2e-agent] onboard/poll did not return auth_key; last payload: ${poll_json:-}" >&2
    exit 1
fi

printf '%s\n' "$auth_key" >"${E2E_HOME}/.config/clawpatrol/wg.conf"
printf 'wireguard\n' >"${E2E_HOME}/.clawpatrol/mode"
printf '%s\n' "$GATEWAY" >"${E2E_HOME}/.clawpatrol/gateway"
if [ -n "$api_token" ]; then
    printf '%s\n' "$api_token" >"${E2E_HOME}/.clawpatrol/api-token"
fi
chown -R e2e:e2e "${E2E_HOME}/.clawpatrol" "${E2E_HOME}/.config"

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
    if su -s /bin/sh e2e -c \
        "CLAWPATROL_BIN=/usr/local/bin/clawpatrol-agent GATEWAY_URL='${GATEWAY}' sh '$t'"; then
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
