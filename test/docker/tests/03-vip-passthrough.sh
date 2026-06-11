#!/bin/sh
# 03-vip-passthrough.sh — guards orchid#184 #2: SSH endpoint declared at
# the policy root, profile excludes it, agent dials the VIP, must reach
# the real upstream (passthrough) instead of being silently RST'd.
#
set -u

out="$(timeout 30s "${CLAWPATROL_BIN}" run -- \
    socat -T 5 - TCP:ssh.example.test:22 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$out" >&2
    echo "clawpatrol run failed during VIP passthrough probe" >&2
    exit "$rc"
fi

printf '%s' "$out" | grep -q 'SSH-2.0-clawpatrol-e2e' || {
    printf '%s\n' "$out" >&2
    echo "VIP passthrough did not reach the SSH stub" >&2
    exit 1
}
printf '%s' "$out" | grep -qi 'Connection reset' && {
    printf '%s\n' "$out" >&2
    echo "VIP passthrough regressed to reset" >&2
    exit 1
}
