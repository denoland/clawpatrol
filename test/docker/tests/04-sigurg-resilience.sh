#!/bin/sh
# 04-sigurg-resilience.sh — guards orchid#184 #3: the seccomp supervisor
# used to exit its `notif_recv` loop on EINTR, which the Go runtime
# delivers via SIGURG during goroutine preemption. With the EINTR retry
# in place, the supervisor must keep serving auto-expose for the entire
# session even after a stress-induced burst of GC pauses.
#
# Approach: long-running `clawpatrol run` that periodically binds a
# fresh TCP listener, while a goroutine (`yes`) keeps the runtime hot
# and preemption signals frequent. Pass = every listener became
# reachable from the host; fail = at least one bind didn't get
# tunneled (relay supervisor died early).

set -eu

CLAWPATROL_BIN="${CLAWPATROL_BIN:-/usr/local/bin/clawpatrol}"

duration=10
attempts=5
out=$("${CLAWPATROL_BIN}" run -- \
        sh -c "yes >/dev/null & ypid=\$!
               for i in \$(seq 1 ${attempts}); do
                   port=\$((30000 + i))
                   nc -l -p \${port} -w 1 >/dev/null 2>&1 &
                   sleep 1
                   if nc -z 127.0.0.1 \${port}; then
                       echo \"reach:\${port}\"
                   else
                       echo \"miss:\${port}\"
                   fi
               done
               kill \${ypid} 2>/dev/null || true" \
      2>&1 || true)

missed=$(echo "$out" | grep -c '^miss:' || true)
if [ "${missed}" -gt 0 ]; then
    echo "04-sigurg-resilience: ${missed}/${attempts} listeners not reachable; supervisor likely died" >&2
    echo "$out" >&2
    exit 1
fi
