#!/bin/sh
# 02-relay-no-spam.sh — guards orchid#184 #1: the relay supervisor used
# to fire one `[clawpatrol relay] inspect listen sockfd: …` line per
# trapped AF_UNIX listen(2) call. With dedup + the AF_UNIX silent skip,
# a gpg-style workload should produce zero such lines.
#
# Runs `gpg --gen-key` (or its kbx init shim) inside `clawpatrol run`,
# captures stderr, and grep-fails if the offending pattern appears.

set -eu

CLAWPATROL_BIN="${CLAWPATROL_BIN:-/usr/local/bin/clawpatrol}"

# Run gpg's first-time init which touches several AF_UNIX listeners
# (gpg-agent control / browser / extra / ssh). Pre-fix this produced
# at least four "inspect listen sockfd" lines per invocation.
out=$("${CLAWPATROL_BIN}" run -- \
        sh -c 'mkdir -p /tmp/gnupg && \
               GNUPGHOME=/tmp/gnupg gpg --list-keys 2>&1 || true' \
      2>&1)

if echo "$out" | grep -q '\[clawpatrol relay\] inspect listen sockfd'; then
    echo "02-relay-no-spam: saw the suppressed log line; AF_UNIX skip regressed" >&2
    echo "$out" | grep '\[clawpatrol relay\]' >&2
    exit 1
fi
