# Docker e2e

End-to-end test harness that runs the clawpatrol gateway and an
agent in two containers and exercises the dispatch paths that
unit tests can't reach — the seccomp listen-trap relay supervisor,
WireGuard L3 interception, and VIP-based SSH dispatch. Built to
catch Docker-environment regressions like orchid#184 (relay
supervisor exiting on SIGURG-driven EINTR, AF_UNIX listen spam,
silent VIP RST when a profile excludes the SSH endpoint).

## Layout

```
test/docker/
├── README.md             this file
├── Dockerfile            single image, the entrypoint selects gateway or agent
├── docker-compose.yml    gateway + agent + SSH-stub sidecar
├── gateway.hcl           minimal policy for the harness
├── entrypoint-gateway.sh launches `clawpatrol gateway`
├── entrypoint-agent.sh   `clawpatrol join` + `clawpatrol run -- <probe>`
└── tests/
    ├── 01-https-mitm.sh        agent → MITM-handled HTTPS endpoint
    ├── 02-relay-no-spam.sh     no `[clawpatrol relay] …` log lines
    ├── 03-vip-passthrough.sh   orchid#184: SSH host w/o profile binding
    └── 04-sigurg-resilience.sh seccomp supervisor survives runtime signals
```

The gateway image embeds the `examples/gateway.example.hcl`-shaped
policy in `gateway.hcl`; the agent image embeds the `clawpatrol`
binary and a small shell harness. CI bootstraps the agent through the
same onboard API used by `clawpatrol join`: it starts an onboard
session, authenticates to the dashboard with the test-only password,
approves the session, polls the WireGuard config, and writes the state
files that `clawpatrol run` consumes.

## Why two images aren't necessary

The `clawpatrol` binary covers every role via subcommand
(`gateway`, `join`, `run`, `relay-supervisor`, `relay-worker`).
A single image with a script entrypoint that dispatches on
`$ROLE` keeps the build matrix small and the cache hits high.

## Running locally

```sh
make build                          # produces ./clawpatrol
cd test/docker
docker compose build                # gateway + agent images share ./clawpatrol
./run-e2e.sh                        # boots compose, runs tests/, tears down
```

Each test under `tests/` is a standalone shell script that returns
non-zero on failure. `run-e2e.sh` walks them in lexical order and
emits a per-test PASS/FAIL line.

## CI integration

`.github/workflows/docker-e2e.yml` runs this harness on every PR.
Job is gated on `make build` succeeding (same artifact, no
duplicate work). Expected runtime: ~90s including the WireGuard
handshake and image build cache miss.

## Capability requirements

`clawpatrol run` opens an unprivileged user namespace, installs a
seccomp filter, and forks a netns. Docker's default seccomp
profile blocks `unshare(CLONE_NEWUSER)` on some kernels and
AppArmor's `docker-default` makes `/proc/<pid>/fd/*` unreadable
from peers — exactly the conditions that produced orchid#184.
The compose file unsets the default seccomp profile and adds
`SYS_ADMIN` to the agent container so the failure mode the test
is meant to catch isn't masked by the harness itself.

## Adding a test

1. Drop a `NN-name.sh` script in `tests/` (lexical ordering picks
   execution order; reserve 00 for setup, 99 for teardown).
2. Exit non-zero on assertion failure with a one-line reason on
   stderr — `run-e2e.sh` reports the stderr line in the summary.
3. Tests run inside the agent container after it has joined the
   gateway and seeded the state files that `clawpatrol run` consumes.

## Known gaps

- WireGuard UDP transport in Docker requires `/dev/net/tun` on the
  gateway; the compose file mounts it. Hosts without TUN support fail
  the harness instead of silently passing because every probe now
  depends on a working `clawpatrol run` session.
- No tsnet/Tailscale coverage — tsnet bootstrap depends on a
  real Tailscale tailnet, which doesn't fit in a hermetic
  harness. The TS-specific paths stay covered by the in-process
  tests under `cmd/clawpatrol/tailscale_*_test.go`.
- The SSH passthrough assertion uses a `socat` banner service rather
  than a full OpenSSH daemon, since the assertion is on whether bytes
  flow through the VIP fallback at all, not on the SSH handshake.
