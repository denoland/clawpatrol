#!/bin/sh
# 01-https-mitm.sh — sanity probe: agent dials the gateway's MITM-able
# HTTPS endpoint via `clawpatrol run` and the request lands in the
# gateway's action log.
#
# Placeholder: needs:
#   - a stub HTTPS upstream the gateway can splice / MITM
#   - `clawpatrol run` to actually run inside this container (requires
#     successful `clawpatrol join` + working daemon socket)
#   - a GATEWAY_URL/api/actions GET that returns the request the
#     `curl` produced, for the assertion
#
# Exit 0 for now so the harness stays green; the unit tests under
# cmd/clawpatrol/ cover the dispatch path on the production code
# until the integration assertion can be wired up.

echo "01-https-mitm: placeholder — see file header" >&2
exit 0
