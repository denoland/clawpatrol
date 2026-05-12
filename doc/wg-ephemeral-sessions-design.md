# Ephemeral WG keypair per `clawpatrol run` session — design

Today every `clawpatrol run` invocation on a device shares the device's
single long-lived WireGuard keypair (set up at `clawpatrol join`). The
gateway can't distinguish concurrent sessions, dashboard tagging is
muddled, and session-scoped features (e.g. the dry-run work in
`cl-d9d`) inherit the same ambiguity.

This document is the investigation + design proposal that precedes
implementation. It mirrors the pattern denoland/unclaw already uses.

## TL;DR

- Add a `sessions` table and a `POST /api/sessions` / `DELETE
  /api/sessions/{id}` endpoint pair. Gateway mints the ephemeral
  keypair, returns the private key in the response, peer is wired
  into the WG device and torn down on explicit DELETE.
- Auth: reuse the per-peer bearer token the client already persists
  at `~/.clawpatrol/api-token`. The bearer proves "I am the approved
  device that owns peer IP X"; the session inherits that approval.
- IP allocation: ephemeral peers draw `/32`s from a dedicated subrange
  inside `WGSubnetCIDR` (top half, e.g. `.128–.254`). Device peers keep
  the bottom half. Out-of-band: bump the default subnet width.
- Teardown: explicit DELETE on graceful exit (signal handler). Plus a
  slow gateway-side sweep for orphaned peers with no recent handshake.
- Linux first. macOS NE stays on the device-static keypair this
  iteration — its single-tunnel-per-extension shape makes per-session
  identity a separate refactor.
- Backwards compat: clients that haven't upgraded keep using the
  device keypair via the existing `wg.conf`. Gateway already accepts
  this path; we are adding, not replacing.

## Phase 1 — current state

### clawpatrol today (gap analysis)

**Device keypair lifecycle.** Generated once at `clawpatrol join`:

- `runJoin()` at [login.go:50](../login.go#L50) drives the device-flow
  onboarding.
- On dashboard approval, `apiOnboardApprove()` at
  [onboard.go:523](../onboard.go#L523) calls
  `newOnboarder(w.ts).MintKey(ctx, reuseIP)` at
  [wireguard.go:727](../wireguard.go#L727).
- `MintKey` generates the keypair (`wgGenKeypair()` at
  [wireguard.go:696](../wireguard.go#L696)), allocates a `/32` via
  `allocateIP()` at [wireguard.go:793](../wireguard.go#L793),
  registers the peer with `WGServer.AddPeer()` at
  [wireguard.go:360](../wireguard.go#L360), and persists
  `(pubkey, ip)` into the `wg_peers` table (migration 0001).
- Client receives the full `wg-quick(5)` config + a one-time
  `api_token` via `apiOnboardPoll()` at
  [onboard.go:654](../onboard.go#L654), and persists them to
  `~/.config/clawpatrol/wg.conf` (chmod 600,
  [login.go:712](../login.go#L712)) and `~/.clawpatrol/api-token`
  (chmod 600, [login.go:673](../login.go#L673)).

**Per-process tunnel on Linux.** `runRun()` at
[run_linux.go:54](../run_linux.go#L54):

- Parses `~/.config/clawpatrol/wg.conf` (`parseRunConf()` at
  [run_linux.go:285](../run_linux.go#L285)).
- Re-execs into a new user+net+mnt namespace with `CAP_NET_ADMIN`
  ([run_linux.go:100–116](../run_linux.go#L100)).
- Child opens `/dev/net/tun`, passes the fd back to the parent via
  SCM_RIGHTS, configures the netns
  ([run_linux.go:213–225](../run_linux.go#L213)) and execs the user
  command.
- Parent wraps the TUN fd in a `wireguard-go` `tun.Device`, builds an
  IPC config via `buildWGIpc()` at
  [run_linux.go:338](../run_linux.go#L338) using the device's static
  key from `wg.conf`, calls `dev.IpcSet` + `dev.Up`.

**Identity**: every concurrent `clawpatrol run` on the same device
uses the same static keypair and shows up on the gateway as the same
WG peer / `/32`.

**macOS.** `runRun` on darwin ([run_darwin.go:80](../run_darwin.go#L80))
shells out to the `Clawpatrol.app` helper, which loads the device's
`wg.conf` into a single `NETransparentProxyProvider` tunnel at
install time. `registerSession()` at
[run_darwin.go:44](../run_darwin.go#L44) is purely an
application-level IPC (`/tmp/clawpatrol.sock`, "register <pid>") so
the extension knows which PIDs to route — no per-session cryptographic
identity. The extension owns one tunnel and one keypair.

**Auth between CLI and gateway.** Two surfaces:

- The onboarding endpoints (`/api/onboard/{start,poll,approve,claim,lookup}`,
  registered at [web.go:237–241](../web.go#L237)) are mostly
  unauthenticated except for `approve` (dashboard secret / tailnet
  operator). The `device_code` itself is a 48-byte one-time secret.
- Steady-state client API uses a per-peer bearer:
  `mintAndPersistPeerAPIToken()` at
  [peer_api_tokens.go:24](../peer_api_tokens.go#L24) mints a 32-byte
  base64 token, persists its SHA-256 in `peer_api_tokens`. The CLI
  presents `Authorization: Bearer <token>`; the gateway resolves it
  to a peer IP via `peerIPForAPIToken()`
  ([peer_api_tokens.go:46](../peer_api_tokens.go#L46)). This currently
  gates `/api/env-pushdown`
  ([web.go:242](../web.go#L242)).

**IP allocation.** `allocateIP()` at
[wireguard.go:793](../wireguard.go#L793) reads used IPs from
`wg_peers`, walks `WGSubnetCIDR` (default `10.55.0.0/24`, see
[main.go:2099](../main.go#L2099)) and returns the first free slot
in `.2–.254`. Sequential, no defrag, no separate range for ephemeral
peers.

**Dashboard.** `agentsList()` at
[agents.go:678](../agents.go#L678) walks the live WG peers
(`EndpointsByIP()` at [wireguard.go:487](../wireguard.go#L487)) and
enriches with onboard metadata. Rendered by
`www/src/components/AgentsTable.tsx`, one row per WG peer.

### unclaw — reference implementation

unclaw (`/home/gastown/gt/unclaw/refinery/rig/`) already does ephemeral
per-session keypairs. End-to-end trail:

- **CLI entry:** `runWrap()` at
  `src/cli.ts:453`. Session name defaults to the command basename
  (`cli.ts:477`). It calls
  `createSessionApi(baseUrl, deviceToken, { name, profileId })` at
  `cli.ts:528`.
- **Client → gateway:** `createSessionApi()` at
  `src/client-api.ts:194` POSTs `/api/sessions` with body
  `{ deviceToken, name, profileId }`. The device token (long-lived,
  established at join time) goes in the body — there is no
  signature.
- **Server handler:** `src/api.ts:614` dispatches
  `POST /api/sessions` to `createSession()` at
  `src/agents.ts:332`. The server:
  - Generates the keypair itself via `generateWgKeyPair()` at
    `agents.ts:298` (Node `crypto.generateKeyPairSync('x25519')`,
    raw 32 bytes extracted from DER and base64-encoded at
    `agents.ts:304–308`).
  - Calls `addPeer()` at `src/wireguard.ts:263` to register the
    pubkey on the running tunnel and allocate IPs
    (`10.77.x.x/32` + `fd77::<hex>/128` via a simple counter at
    `wireguard.ts:275–282`).
  - Inserts the session row at `agents.ts:376–392`
    (`(wg_public_key, wg_private_key, wg_ip, session_token, …)`).
  - Returns `wgPrivateKey`, `wgServerPublicKey`, `wgPeerIp`,
    `wgPeerIpv6`, `wgEndpoint`, plus a separate `sessionToken`
    used for proxy auth (`api.ts:642–655`).
- **Teardown:** the CLI registers a cleanup callback at
  `cli.ts:580–601` that issues `DELETE /api/sessions/{id}`. Signal
  handlers for SIGINT/SIGTERM/SIGHUP at `cli.ts:602–606` invoke
  the cleanup. Server handler at `api.ts:932–940` calls
  `deleteSession()` at `agents.ts:738`, which removes the WG peer
  (`removePeer()` at `wireguard.ts:317`), deletes the session row,
  and clears in-memory indices. No idle timeout — relies on the
  explicit DELETE.
- **Persistence across gateway restart:** on boot, `main.ts:159–161`
  calls `getWireGuardSessions()` and re-installs each session as a
  peer.
- **macOS:** the same gateway-minted keypair is shipped into the NE
  via XPC (`runMacOS()` at `cli.ts:225` invokes
  `tunnelActivate(...)` from `src/xpc.ts:17`). The NE does not have
  per-PID cryptographic identity; the CLI starts a fresh tunnel in
  the NE per `run`. unclaw's NE supports concurrent tunnels in a
  way clawpatrol's currently does not.
- **Dashboard:** sessions render as rows nested under their parent
  device. `dashboard/src/components/DevicesPage.tsx:222–237` filters
  sessions by `deviceId` and emits a table row per session
  (`DevicesPage.tsx:424–432`).
- **Backwards compat:** unclaw does not have a static-keypair path;
  every `run` mints a session.

## Phase 2 — open questions, with positions

### Q1. How does the gateway attest an ephemeral pubkey to its parent device?

**Position:** **Bearer token, no signature.** The CLI presents the
per-peer API token it already stores at `~/.clawpatrol/api-token`.
The gateway resolves it to a peer IP via the existing
`peerIPForAPIToken()` path
([peer_api_tokens.go:46](../peer_api_tokens.go#L46)), and the session
inherits that peer IP's approval + profile.

*Why bearer over signature.* The per-peer token is already minted,
persisted, and revocable. unclaw uses the same shape. A signature
scheme would require a second client-side state file (device
long-term signing key) and a new verification path in the gateway
for no real security benefit over the bearer — the bearer can
already be exfiltrated equivalently to a signing key.

*Why "session inherits peer approval"* rather than re-running
approval. Each session is conceptually a child of an already-approved
device; the operator approved the device, not each fork.

### Q2. IP binding for ephemeral peers

**Position:** **Ephemeral peers get their own `/32`** (otherwise
WG can't distinguish them on the wire — same pubkey = same peer
would collapse them). They do **not** inherit the device's external
IP binding heuristic — i.e. we do not refuse the registration if
the session's external IP differs from the device's. We trust the
bearer.

*Why not bind external IP.* External IP-binding today is a fragile
heuristic for catching token theft on long-lived sessions
(`first_seen_external_ip`). For short-lived ephemeral sessions the
ergonomics cost (NAT-rebind during session = auto-revoke) outweighs
the security gain, and the auth still goes through the bearer.

### Q3. Lifetime / cleanup trigger

**Position:** **Explicit DELETE on graceful exit + gateway-side
sweep.**

- CLI registers SIGINT/SIGTERM/SIGHUP handlers + defers a
  `DELETE /api/sessions/{id}` call on tunnel teardown in
  `run_linux.go`.
- Gateway runs a periodic sweep (e.g. every 5 min) that drops
  ephemeral peers with no handshake in the last hour. Catches
  SIGKILL'd CLIs and crashed boxes.

*Why both.* Explicit DELETE keeps the dashboard tidy on the common
path. The sweep is the safety net — unclaw doesn't have it and
leaks peers on hard exits; that's a real bug we should not
inherit.

*Cap concurrent ephemeral peers per device* (e.g. 32) to bound the
blast radius of a buggy or hostile client. Reject new sessions over
the cap with `429`.

### Q4. Subnet allocation

**Position:** **Carve a dedicated ephemeral range out of
`WGSubnetCIDR`.** Top half of the configured subnet (e.g. `.128–.254`
in a `/24`) is the ephemeral pool; bottom half (`.2–.127`) stays for
device peers. The split is computed at gateway boot from the
configured CIDR width.

Out-of-band recommendation: **widen the default to `/22`** in a
follow-up bead. `/24` was already tight at scale; ephemeral peers
make it tighter.

*Alternative considered:* recycle device IPs as "primary" and give
ephemeral peers IPs from an entirely separate subnet (e.g.
`10.55.1.0/24` as ephemeral, `10.55.0.0/24` as devices). Rejected
because the gateway's gVisor netstack and route table currently
assume a single subnet; multi-subnet is more change than we need.

### Q5. macOS

**Position:** **Linux-only this iteration.** macOS NE keeps using
the device's static keypair from `wg.conf`.

*Why.* clawpatrol's NE (`macos/ClawpatrolExtension/`) holds **one**
tunnel and **one** keypair, loaded at install time. unclaw's NE
supports concurrent tunnels — that's a separate refactor (multiple
`NETransparentProxyProvider` tunnels, multiple userspace WG
instances, multiplexed XPC). Out of scope for this bead.

The existing `registerSession()` PID-tracking ([run_darwin.go:44](../run_darwin.go#L44))
already gives per-session attribution at the application layer on
macOS — enough for the dry-run dispatcher in `cl-d9d`, which is the
near-term consumer. File a follow-up bead for "macOS NE: per-session
WG identity".

### Q6. Dashboard rendering

**Position:** **Group ephemeral peers under their parent device.**
Each device row shows a "N active sessions" badge; clicking
expands to a list of `(session-name, ephemeral-ip, started-at)`.
Out of scope for this bead: implementing the React change. This bead
ships the data shape (`sessions` table, `GET /api/sessions?device_ip=…`),
and a follow-up bead does the UI.

*Data shape proposed*

```
sessions
  id           TEXT PRIMARY KEY      -- random 16 bytes b64
  device_ip    TEXT NOT NULL         -- parent device's WG /32
  name         TEXT                  -- defaults to command basename
  wg_pubkey    TEXT NOT NULL UNIQUE
  wg_ip        TEXT NOT NULL UNIQUE  -- ephemeral /32 in upper range
  created_ns   INTEGER NOT NULL
  last_seen_ns INTEGER NOT NULL      -- updated by WG handshake observer
```

### Q7. Backwards compatibility

**Position:** **The static `wg.conf` path remains valid.** Clients
that haven't upgraded keep working — they show up as the device peer
with no sessions. Old CLI + new gateway: works. New CLI + old
gateway: CLI detects `404 on POST /api/sessions` and falls back to
the static path with a warning.

The gateway's `WGServer.AddPeer()` is called for both device peers
(via `MintKey`) and ephemeral peers (via the new session handler);
the WG layer doesn't care.

## Phase 3 — implementation outline

(Sketch, pending Phase 2 sign-off.)

1. **Schema migration 0007:** add `sessions` table per Q6, plus index
   on `(device_ip)`.
2. **Gateway endpoints:**
   - `POST /api/sessions` — `authSelfAuthenticating` (bearer →
     device_ip). Mints keypair, allocates ephemeral `/32`, calls
     `AddPeer`, inserts row, returns
     `{session_id, wg_private_key, wg_public_key, wg_ip,
     wg_server_public_key, wg_endpoint, wg_ipv6}`.
   - `DELETE /api/sessions/{id}` — same auth, `RevokePeerByIP` on
     the ephemeral IP, deletes row.
   - Background goroutine: sweep ephemerals with no handshake in
     `wg_idle_timeout` (default 1h).
3. **CLI:** `run_linux.go` gets a new path before `parseRunConf`:
   - If `~/.clawpatrol/api-token` exists and gateway responds 200 to
     `POST /api/sessions`, use the returned ephemeral config and
     register a deferred DELETE on exit.
   - Else fall back to `parseRunConf` on the static `wg.conf`.
4. **Tests:**
   - Unit: `generateWgKeyPair()` shape (curve25519, 32 bytes).
   - Integration: two concurrent `clawpatrol run` invocations on
     the same device produce two distinct WG peers and route to
     two distinct dashboard entries
     (`integration_two_sessions_test.go`).
   - Cleanup: kill one session, verify peer dropped from `wg_peers`
     within timeout window.
   - Backwards-compat: a CLI using the static-key path still works
     against the new gateway.
5. **Observability:** session create / delete / sweep events emitted
   through the existing telemetry hook in `telemetry.go`.

## Out of scope

- `--whole-machine` mode — intentionally uses the device's static
  identity; ephemeral keys make no sense there.
- macOS NE per-session WG identity (separate bead).
- The dashboard React change for nested session rows (separate
  bead, depends on this).
- Replacing the device's main keypair concept; devices still own a
  long-lived identity for `--whole-machine` and as the parent of
  ephemeral sessions.
