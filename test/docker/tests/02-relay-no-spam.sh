#!/bin/sh
# 02-relay-no-spam.sh — guards orchid#184 #1: the relay supervisor used
# to fire one `[clawpatrol relay] inspect listen sockfd: …` line per
# trapped AF_UNIX listen(2) call. With dedup + the AF_UNIX silent skip,
# a gpg-style workload should produce zero such lines.
#
set -u

out="$(timeout 30s "${CLAWPATROL_BIN}" run -- sh -eu -c '
    rm -f /tmp/clawpatrol-e2e.sock
    socat UNIX-LISTEN:/tmp/clawpatrol-e2e.sock,fork EXEC:/bin/cat &
    p=$!
    sleep 1
    kill "$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
' 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$out" >&2
    echo "clawpatrol run failed during AF_UNIX listener probe" >&2
    exit "$rc"
fi

printf '%s' "$out" | grep -q '\[clawpatrol relay\] inspect listen sockfd' && {
    printf '%s\n' "$out" >&2
    echo "AF_UNIX listener produced relay inspect spam" >&2
    exit 1
}

exit 0
