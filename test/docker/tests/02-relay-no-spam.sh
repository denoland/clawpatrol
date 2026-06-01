#!/bin/sh
# 02-relay-no-spam.sh — guards orchid#184 #1: the relay supervisor used
# to fire one `[clawpatrol relay] inspect listen sockfd: …` line per
# trapped AF_UNIX listen(2) call. With dedup + the AF_UNIX silent skip,
# a gpg-style workload should produce zero such lines.
#
# Placeholder until `clawpatrol run` can be driven from inside this
# container — that needs a working `clawpatrol join` step ahead of it
# (currently no-trust + non-tailnet join is half-wired in
# entrypoint-agent.sh). Once it runs, the body should be:
#
#   out=$("${CLAWPATROL_BIN}" run -- \
#           sh -c 'GNUPGHOME=/tmp/gnupg gpg --list-keys' 2>&1)
#   echo "$out" | grep -q '\[clawpatrol relay\] inspect listen sockfd' \
#       && { echo "AF_UNIX skip regressed" >&2; exit 1; }
#
# Until then, exit 0; the dispatch path is covered by the unit tests
# under cmd/clawpatrol/relay_linux_test.go.

echo "02-relay-no-spam: placeholder — see file header" >&2
exit 0
