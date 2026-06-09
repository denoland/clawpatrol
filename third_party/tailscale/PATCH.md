# Vendored, patched `tailscale.com`

This directory is a **pruned copy of `tailscale.com` v1.96.5** carrying a
single local patch. It exists only so we can carry that patch until it
lands upstream.

It is wired in via a `replace` directive in the repo-root `go.mod`:

    replace tailscale.com => ./third_party/tailscale

## What "pruned" means

Only the `tailscale.com/...` packages that `clawpatrol` actually compiles
are kept (the import closure of `./cmd/clawpatrol` and the test suite across
all release targets, plus whatever `go mod tidy` requires). Upstream content
we never build — the `cmd/` binaries, the k8s operator, release/packaging
tooling, most `testdata`, and upstream's own `*_test.go` files — has been
removed to keep the tree small. The kept package directories are otherwise
unmodified (embedded assets preserved), except for the one patch below.

## The patch

One file is modified: `net/tstun/wrap.go`, function `injectedRead`.

Netstack-originated outbound packets (everything a `tsnet` app sends) reach
the WireGuard tun via `InjectOutboundPacketBuffer`, whose read path
(`injectedRead`) skips the outbound packet filter. The normal OS-read path
(`Read` -> `filterPacketOutboundToWireGuard`) runs `Filter.RunOut`, which
records the reverse-flow tuple in the filter's connection-tracking LRU.
Because the injected path skips it, the reverse flow is never recorded, so
when the reply arrives `Filter.RunIn` finds no cached flow and — unless an
explicit ACL rule happens to admit the reply's source — drops it.

The effect: a userspace/netstack exit-node client silently drops inbound
**UDP** replies. TCP is unaffected (`RunIn` admits non-SYN TCP via the
established-connection heuristic). This breaks native UDP relay through the
gateway (`GetUDPHandlerForFlow`): the gateway echoes/relays the datagram
correctly but the client never receives the reply.

The patch makes `injectedRead` run `RunOut` on injected packets too, so the
reverse-flow tuple is recorded and the reply is admitted.

## Upstream tracking

- Upstream issue: https://github.com/tailscale/tailscale/issues/20064

## How to stop vendoring (do this once upstream is fixed)

1. Delete `third_party/tailscale/`.
2. Remove the `replace tailscale.com => ./third_party/tailscale` directive
   from the root `go.mod`.
3. Bump the `tailscale.com` requirement to the first release that contains
   the upstream fix.
4. `go mod tidy && go build ./... && go test ./...`.

## Verifying the patch is the only source change

Because the tree is pruned, a plain `diff -r` against the upstream module is
noisy (it reports the removed files). To confirm the only *content* change
to a kept file is the patch, compare just the surviving files:

    go mod download tailscale.com@v1.96.5
    UP="$(go env GOMODCACHE)/tailscale.com@v1.96.5"
    cd third_party/tailscale
    find . -type f ! -name PATCH.md | while read -r f; do
      diff -q "$f" "$UP/$f" >/dev/null 2>&1 || echo "differs: $f"
    done
    # expected sole line: differs: ./net/tstun/wrap.go
