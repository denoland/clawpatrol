#!/bin/sh
# 04-sigurg-resilience.sh — guards orchid#184 #3: the seccomp supervisor
# used to exit its `notif_recv` loop on EINTR, which the Go runtime
# delivers via SIGURG during goroutine preemption. With the EINTR retry
# in place, the supervisor must keep serving auto-expose across runtime
# signals.
#
set -eu

out="$(timeout 30s "${CLAWPATROL_BIN}" run -- sh -eu -c '
    sleep 1
    pkill -URG -f "clawpatrol.*relay-supervisor" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        socat TCP-LISTEN:0,reuseaddr,fork EXEC:/bin/cat &
        p=$!
        sleep 0.2
        kill "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null || true
    done
' 2>&1)"

printf '%s' "$out" | grep -q '\[clawpatrol relay\] notif_recv: interrupted system call' && {
    printf '%s\n' "$out" >&2
    echo "relay supervisor exited on SIGURG/EINTR" >&2
    exit 1
}
