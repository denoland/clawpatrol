# Localhost upstreams → source-device tunnel IP (design)

Status: **proposal** (cl-ukn8). Not yet implemented. Depends on the
run-time host-loopback forwarder from PR #589 (`clawpatrol run`), which
at time of writing lives on a side branch and is **not merged to main**.

## Problem

An endpoint may legitimately declare a loopback upstream:

```hcl
endpoint "local_pg" "postgres" {
  host = "localhost:5432"   # or "127.0.0.1:5432"
}
```

`localhost` is a hostname, not an IP literal, so it is treated as a
resolvable host and claims a DNS-VIP at policy build
(`hasResolvableHostname`, `internal/config/compile.go:527`;
`RebuildFromPolicy`, `cmd/clawpatrol/dnsvip/dnsvip.go`). The agent
resolves `localhost` to that VIP, connects to it inside the WG/tsnet
netstack, and the gateway dispatches the connection
(`handleVIPConn` → `dispatchConnEndpoint`, `cmd/clawpatrol/main.go:1621`,
`:1703`).

The plugin then picks its upstream from the declared hosts and dials it:

- postgres: `ch.DialUpstream(ctx, "tcp", upstreamAddr)`,
  `internal/config/plugins/endpoints/postgres.go:271`
- ssh: `pickUpstream(ep.Hosts, ch.DstPort)` then
  `ch.DialUpstream(...)`, `internal/config/plugins/endpoints/ssh.go:151`

`DialUpstream` is the closure built in `dispatchConnEndpoint`
(`cmd/clawpatrol/main.go:1736`); it calls `g.dialThrough`
(`cmd/clawpatrol/tunnel.go:480`), which — absent a tunnel — falls back
to `g.dialer.DialContext`. That dialer runs on the **gateway's host
network**, so `localhost:5432` resolves to the *gateway's* own
loopback. The agent meant *its own* localhost (the postgres running on
the agent's host). Wrong target, silent.

This is the VIP/gateway-path counterpart to PR #589, which solved the
same "reach the agent host's loopback" problem for the
`clawpatrol run` wrapped-command path only.

## Proposal

When a device's profile uses an endpoint whose chosen upstream host is
loopback, rewrite the gateway's dial target from `localhost:port` to
**the source device's tunnel IP**, and dial it **back through the
netstack** (not the host dialer). On the device side, the existing
PR #589 reverse-relay redirects that inbound `tunnelIP:port` connection
to the device's host loopback.

```
agent app ──dial localhost:5432──▶ DNS-VIP ──▶ gateway VIP conn
gateway: upstream host is loopback
      └─ rewrite target → <sourceDeviceTunnelIP>:5432
      └─ dial back THROUGH the netstack (ts.Dial / wg netstack), not host net
device netns: inbound on tunnelIP:5432
      └─ PR #589 reverse-relay REDIRECT → host 127.0.0.1:5432 (real postgres)
```

The source device tunnel IP is already in hand at dispatch:
`pip := peerIP(c)` in `dispatchConnEndpoint`
(`cmd/clawpatrol/main.go:1710`), captured by the `DialUpstream` closure.

## Open questions — resolved

### 1. How are localhost upstreams declared / validated in HCL?

**Decision: keep the existing `host`/`hosts` syntax; detect loopback at
compile time; no new HCL surface.** `localhost:8443` is already a
documented, valid host entry (`internal/config/testdata/full.hcl:347`)
and passes `hostmatch.ValidateHost`
(`internal/config/plugins/endpoints/util.go:40`). A loopback upstream
is just a host whose hostname is `localhost`/`127.0.0.1`/`::1`
(reuse `isLoopback`, `internal/config/config.go:1537`).

Add at compile time (`compileEndpoint`, `internal/config/compile.go`):

- A per-host `Loopback bool` flag on the compiled host (or a
  `CompiledEndpoint.LoopbackHosts map[string]bool` keyed by `host:port`)
  so the dispatch path does not re-parse strings per connection.
- Validation: a loopback upstream requires the **reverse-relay
  capability** on the device side. Reject (or warn) a loopback upstream
  on an endpoint reached over an explicit `tunnel = ...` block, since
  the tunnel transport (kubectl-portforward-ssh, etc.) is a different
  device than the source agent — "the agent's own localhost" is only
  meaningful for the direct VIP path. Loopback + explicit tunnel is a
  config error.
- A loopback upstream still claims a VIP (it must, to be intercepted),
  so no change to `RequiresVIP`.

### 2. Per-device VIP→tunnel-IP mapping lifecycle + netns-side redirect

**Decision: no persistent per-device VIP allocation. Resolve to the
tunnel IP at dial time, per connection.** The VIP table stays
device-agnostic (one VIP per hostname, as today). The
device-specificity is applied late, in `DialUpstream`, using
`peerIP(c)` of the live connection. This avoids a per-device VIP
lifecycle entirely and matches the existing model where the same VIP
serves all devices and the profile filter + dispatch decide routing.

The netns-side redirect is **not new** — it is exactly the PR #589
reverse-relay (agent-netns worker installs an iptables nat REDIRECT,
host-netns supervisor bidi-copies to host loopback). The only new
requirement is that the relay must accept connections arriving on the
**tunnel IP** (from the gateway), not only `127.0.0.1` from the wrapped
command. See "Device-side dependency" below.

### 3. Approval flow + dashboard rendering

**Decision: no change to the approval chain; cosmetic dashboard change
only.** Approval keys off endpoint + rule + profile + agent IP
(`runApproveChain`, via the `Approve` closure in
`dispatchConnEndpoint`, `cmd/clawpatrol/main.go:1764`) — none of which
the rewrite touches. The dial-target rewrite happens *after* the
allow/approve decision, inside `DialUpstream`.

Dashboard: the event `Host` is the dialed hostname (`localhost`,
`eventHost`, `cmd/clawpatrol/main.go:1718`). Rendering raw `localhost`
is ambiguous across devices. Render it as `localhost (→ <device>)` or
keep `Host=localhost` and surface the resolved tunnel IP in the request
detail facets so operators can see which device's loopback was hit.

## Implementation sketch

### Gateway side (this repo, this feature)

The single choke point is the `DialUpstream` closure
(`cmd/clawpatrol/main.go:1736`). `pip` is already captured.

```go
DialUpstream: func(ctx context.Context, network, addr string) (net.Conn, error) {
    if addr == "" {
        return nil, fmt.Errorf("conn dispatch: plugin gave empty upstream addr")
    }
    // Loopback upstream: the agent meant ITS OWN localhost, not the
    // gateway's. Redirect to the source device's tunnel IP and dial
    // back through the netstack so the device-side reverse-relay
    // (PR #589) lands it on the device's host loopback.
    if ep.IsLoopbackUpstream(addr) { // compile-time flag, not string re-parse
        host, port, err := net.SplitHostPort(addr)
        _ = host
        if err != nil {
            return nil, err
        }
        return g.dialBackToDevice(ctx, network, net.JoinHostPort(pip, port))
    }
    return g.dialThrough(ctx, ep, network, addr)
},
```

`dialBackToDevice` must dial **into the netstack**, not the host
network:

- **tsnet mode**: `tsnet.Server.Dial` routes through the tailnet to the
  peer (`run_tsnet_common.go:43` already uses `ts.Dial` as a transport;
  the gateway holds the server via `openListener`, `tailscale.go:83`).
- **WG mode**: dial via the embedded gVisor netstack
  (`tsnet.Server.Sys().Netstack` → `*netstack.Impl`, see
  `installTsnetUDPDNSCatchAll`, `tailscale.go:263`), targeting the
  peer's WG tunnel IP. `g.dialer` / `net.DialTimeout`
  (`wgRelay`, `main.go:3442`) are host-network and must **not** be used
  here.

Plumb the netstack dialer onto `Gateway` at startup (where the WG
server / tsnet server is created, `main.go:3027`, `:3077`) so
`dialBackToDevice` has a handle.

### Device-side dependency (PR #589 + extension)

PR #589's reverse-relay redirects `127.0.0.1:*` connect()s *from the
wrapped command* to the host loopback. For this feature the relay must
also catch connections arriving **from the gateway on the tunnel IP**.
Two options:

- **A (preferred): widen the REDIRECT match** so the nat rule captures
  `-d <tunnelIP> --dport <p>` (or the netns's TUN-facing address) in
  addition to `127.0.0.1`, routing both to the same host-loopback
  supervisor path. The SO_MARK/`-m mark RETURN` exemption that lets the
  worker's own dials bypass still applies unchanged.
- **B: a dedicated listener** on the tunnel IP per exposed loopback
  port that forwards to the supervisor. More moving parts; only if the
  iptables widening proves infeasible across the netns address layout.

This is its own bead — it cannot land until #589 is merged to main.

## Staging / dependency order

1. **Blocked on #589 merge to main.** Verify the reverse-relay is in
   `main`; this feature's device side extends it.
2. **cl-ukn8a — compile-time loopback detection + validation.** Add the
   loopback flag/helper on `CompiledEndpoint`, reject loopback +
   explicit-tunnel. Pure config change, fully unit-testable
   (`internal/config/compile_test.go`), independent of #589.
3. **cl-ukn8b — gateway netstack dial-back.** Plumb the netstack dialer
   onto `Gateway`; add `dialBackToDevice`; rewrite the `DialUpstream`
   closure. Unit-test the rewrite decision; integration-test needs the
   device side.
4. **cl-ukn8c — device-side reverse-relay tunnel-IP capture** (option A
   above). Depends on #589 + cl-ukn8b.
5. **cl-ukn8d — dashboard rendering** of `localhost (→ device)`.

Step 2 is shippable and useful on its own (it makes a loopback +
explicit-tunnel mistake a load-time error instead of a silent
wrong-host dial). Steps 3–4 are the end-to-end feature and gate on #589.

## Threat model notes

- The rewrite only ever targets `peerIP(c)` — the *source* device's own
  tunnel IP. A device can only ever reach its own loopback, never
  another device's, because `pip` is the connection's authenticated WG
  peer. No cross-device punch-through.
- Dialing must go through the netstack, so the target is constrained to
  the tailnet/WG address space; it cannot be steered at the gateway
  host's services or arbitrary IPs.
- Loopback + explicit tunnel is rejected at compile time, closing the
  "redirect to a third party" ambiguity.
- The device-side REDIRECT widening inherits #589's SO_MARK exemption
  and CAP_NET_ADMIN-less wrapped command — the agent app still cannot
  bypass the relay.
