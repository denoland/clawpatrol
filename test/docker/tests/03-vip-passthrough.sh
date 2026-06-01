#!/bin/sh
# 03-vip-passthrough.sh — guards orchid#184 #2: SSH endpoint declared at
# the policy root, profile excludes it, agent dials the VIP, must reach
# the real upstream (passthrough) instead of being silently RST'd.
#
# Placeholder: needs three pieces still to be wired in the harness:
#   - extra_hosts entry mapping ssh.example.test to a routable IP
#     reachable from the gateway's host network
#   - a stub SSH-shaped TCP server reachable at that IP:22 from inside
#     the gateway's userns (host networking on the gateway service or
#     a third compose service joined to the same bridge)
#   - the agent's /etc/resolv.conf must route through the gateway so
#     that ssh.example.test resolves to the VIP rather than the docker
#     embedded DNS (currently true once `clawpatrol join --whole-machine`
#     is wired into entrypoint-agent.sh).
#
# Until those land, exit 0 to keep the harness green; the unit-level
# coverage in cmd/clawpatrol/vip_passthrough_test.go exercises the same
# dispatch path on the production code path.

echo "03-vip-passthrough: placeholder — see file header for the open hooks" >&2
exit 0
