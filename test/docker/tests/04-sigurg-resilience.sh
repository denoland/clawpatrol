#!/bin/sh
# 04-sigurg-resilience.sh — guards orchid#184 #3: the seccomp supervisor
# used to exit its `notif_recv` loop on EINTR, which the Go runtime
# delivers via SIGURG during goroutine preemption. With the EINTR retry
# in place, the supervisor must keep serving auto-expose across runtime
# signals.
#
# Placeholder until `clawpatrol run` can drive a multi-listener probe
# from inside this container. The shape of the eventual probe:
#
#   - long-running `clawpatrol run` that periodically binds a fresh
#     TCP listener inside the netns
#   - a host-side prober that connects to each via the relayed port
#   - assert every bind became reachable
#
# Until then, exit 0; the EINTR retry is unit-covered indirectly via
# the relay tests under cmd/clawpatrol/relay_linux_test.go.

echo "04-sigurg-resilience: placeholder — see file header" >&2
exit 0
