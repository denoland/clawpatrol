#!/bin/sh
# 03-vip-passthrough.sh — guards orchid#184 #2: SSH endpoint declared at
# the policy root, profile excludes it, agent dials the VIP, must reach
# the real upstream (passthrough) instead of being silently RST'd.
#
# Stubs the "real upstream" with socat so the test stays hermetic — we
# only assert that the bytes traverse the gateway's passthrough, not
# that the SSH handshake completes.

set -eu

CLAWPATROL_BIN="${CLAWPATROL_BIN:-/usr/local/bin/clawpatrol}"

# Stub upstream on a high port: writes a fixed banner on accept then
# closes. Reachable from inside the agent netns via the host's loopback
# (the gateway will dial 127.0.0.1 from its own host network, which is
# the agent container too in this harness).
PORT="$(/usr/local/bin/clawpatrol _internal-pick-port 2>/dev/null || echo 22022)"
( socat TCP-LISTEN:"${PORT}",bind=127.0.0.1,reuseaddr,fork \
        SYSTEM:'printf "STUB-SSH-2.0\r\n" && cat >/dev/null' \
  ) &
stub_pid=$!
trap 'kill ${stub_pid} 2>/dev/null || true' EXIT

# Give socat a beat to bind.
sleep 0.5

# Dial via VIP'd hostname (gateway DNS interception rewrites ssh.example.test
# → its allocated VIP). Pre-fix this dial returned a TCP RST in the
# agent netns; post-fix the gateway passthrough forwards bytes to the
# socat stub, which writes the banner.
got=$("${CLAWPATROL_BIN}" run -- \
        sh -c "exec 3<>/dev/tcp/ssh.example.test/22 && \
               head -c 13 <&3" 2>/dev/null || true)

if [ "$got" != "STUB-SSH-2.0
" ]; then
    echo "03-vip-passthrough: expected stub SSH banner, got: ${got}" >&2
    exit 1
fi
