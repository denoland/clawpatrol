# ADR: ClickHouse native protocol dispatch

**Status:** accepted

**Decision:** terminate the ClickHouse native protocol in
`config/plugins/endpoints/clickhouse_native`, and reach that
runtime through **three** dispatch paths layered in priority
order — DNS-VIP for hostname bindings, a direct-IP `ConnIndex`
lookup for IP-literal bindings, and a port-based dispatch on
`:9000` / `:9440` that mirrors the `:5432` postgres path. The
prior framing of "direct-IP **versus** VIP" was a false dilemma:
the question is not which dispatch wins, but how a flow that
might be ClickHouse is steered into the same protocol terminator.

## Context

The promiscuous WireGuard forwarder accepts SYNs to any
destination IP/port (`main.go:tcpDispatch`). For each flow it
must pick one of:

- terminate a known wire protocol in a plugin,
- relay bytes verbatim to the real upstream (`wgRelay`).

`https` and `kubernetes` recover endpoint identity at TLS time by
peeking the SNI. Postgres has no SNI but uses a well-known port
(`:5432`) plus a profile lookup. SSH is hostname-identified —
`ssh build.example.com` and `ssh prod.example.com` both arrive on
`:22` of distinct upstreams — so it leans on DNS-VIP to recover
the agent-dialed name from the destination IP.

ClickHouse native sits awkwardly in this space:

- **No SNI.** Plaintext on `:9000` and TLS on `:9440`, but the
  TLS variant carries no application-layer hostname. The Hello
  packet, which the client sends *after* the TCP/TLS handshake,
  carries the username/database, not the cluster identity.
- **Multi-host clusters.** ClickHouse Cloud and managed
  deployments expose one logical cluster behind a hostname whose
  DNS rotates between many IPs. Pre-resolving every IP at policy
  build is fragile.
- **Multiple agent shapes.** The official `clickhouse-client`
  CLI, `clickhouse-driver` (Python), `clickhouse-go`,
  JetBrains DataGrip, and Grafana's CH plugin each dial differently
  — some use the cluster hostname, some accept an IP literal in a
  connection string, some negotiate compression up front, some
  toggle compression per query.

The dispatch decision **must** happen before the first agent byte
is read, since picking the wrong handler closes (or worse,
mis-frames) the connection.

## Options considered

### Option A — TCP passthrough with sidecar inspection ("VIP packet-sniff")

The wording in the inbox issue described "VIP approach: intercept
at the TCP level using a virtual IP, inspect packets without full
protocol termination". Concretely this would mean:

1. Allocate a VIP per hostname (already done by `dnsvip`).
2. Forward bytes both ways with `io.Copy`.
3. Sniff query strings opportunistically out of the byte stream.

Tried in a scratch branch; rejected on three counts.

1. **Correctness.** ClickHouse native is variable-length
   VarInt-framed with optional LZ4/ZSTD compression. There is no
   reliable text fragment to grep for. A Query packet is
   `code:VarInt | id:string | client_info:VarInt+blob | settings | … | body:string | compression:VarInt | data_blocks…`.
   Recovering the SQL body needs full VarInt + ClientInfo decode
   anyway — i.e. exactly the work the terminator does.
2. **Credential injection becomes impossible.** The Hello packet
   embeds the agent's username and password as length-prefixed
   strings. Passthrough cannot rewrite those without re-emitting
   the surrounding VarInt frame, which means partial
   termination. Once we're partial we own the rest of the wire
   anyway.
3. **Deny semantics are broken.** Postgres signals a denial with
   a Backend `ErrorResponse` followed by `ReadyForQuery` so the
   client stays in the session. The ClickHouse equivalent is a
   `ServerCodeException` with a structured error code (we use
   `497 ACCESS_DENIED`). A sniff-only path can drop bytes on the
   floor but cannot synthesise that packet without taking over
   the session — which is what termination *is*.

### Option B — direct-IP only

Drop the VIP allocation; require operators to pre-declare upstream
IPs. The forwarder reads `dstIP`, consults `ConnIndex`, finds the
endpoint, terminates the protocol.

Pros:

- One dispatch surface; no DNS interception.
- No VIP allocator state to persist.

Cons:

- **Cloud ClickHouse breaks.** Managed clusters expose a hostname
  whose A records change behind the scenes. Pre-resolving at
  policy build pins to whatever the gateway saw at that moment;
  the next failover lands outside the index and the flow
  passthroughs (no policy enforcement).
- **Operators have to enumerate.** A multi-shard self-hosted
  cluster typically has 3–9 IPs. `hosts = ["10.0.0.5",
  "10.0.0.6", …]` is brittle when one is added or rotated.
- **Pod IPs.** In Kubernetes the upstream IP is a Service or
  ClusterIP, and Service VIPs can be reassigned across cluster
  restores; even worse, operators sometimes want to dial pod IPs
  directly.

### Option C — VIP only

The DNS responder answers ClickHouse hostnames with a stable VIP;
the forwarder routes any port on that VIP to the runtime
(`handleVIPConn`). VIPs persist to `dnsvip.json` so they survive
restart.

Pros:

- Hostnames resolved at *dial time* — DNS rotation is opaque to
  the gateway. The terminator dials the real upstream when the
  session begins, so the freshest A record wins.
- One stable identity per cluster (the hostname), so a single
  endpoint binding covers all replicas.

Cons:

- **IP-literal bindings fall through.** A self-hosted ClickHouse
  reached as `hosts = ["172.17.0.1:9000"]` has no DNS query to
  intercept, so there's no VIP. The flow has to be picked up by
  *some* other path.
- **Trust model.** DNS is the recovery key for endpoint identity.
  If an agent bypasses the gateway's resolver (hardcoded
  `1.1.1.1`, etc.) the VIP table is never consulted — but in
  practice the WG netstack routes any `:53` datagram into the
  gateway regardless of the agent's resolver setting, so this is
  defended in depth.

### Option D — port-based dispatch ("postgres model")

The forwarder special-cases `:9000` and `:9440` and unconditionally
calls a `handleClickhouseNativeConn` that picks the first
ClickHouse-native endpoint in the device's profile (like
`handlePostgresConn` + `firstPostgresEndpoint`).

Pros:

- Catches *all* ClickHouse traffic from a profile that has any
  `clickhouse_native` endpoint, regardless of how the agent
  reached the upstream (hostname, IP literal, freshly-rotated
  Cloud IP not in the index).
- Simple to reason about: "does the profile have a CH endpoint?
  yes → terminate; no → relay."

Cons:

- **Single-endpoint heuristic.** When two `clickhouse_native`
  endpoints in the same profile point at different clusters,
  "first wins" picks one arbitrarily for any flow whose dst IP
  isn't in `ConnIndex`. Mitigated by trying `ConnIndex` first.
- **Port collision.** Some operators run unrelated services on
  9000 (Portainer agent, kdb+ legacy ports). Mitigated by
  fall-through to relay when no CH endpoint is in the profile —
  i.e. the dispatch only fires when an operator has explicitly
  declared they want ClickHouse policy on this profile.

## Decision

Adopt **all three real options layered**:

1. **DNS-VIP** (highest priority). ClickHouse endpoints with
   hostname `hosts` claim a VIP per hostname. The forwarder
   recognises VIP destinations before anything else and routes to
   `handleVIPConn`. Hostnames stay the cluster identity; DNS
   rotation is opaque to clawpatrol.
2. **Direct-IP via `ConnIndex`** (medium). ClickHouse endpoints
   with IP-literal `hosts` fold into `ConnIndex` at policy build.
   In the port-based handler (and in the catch-all branch) the
   index lookup wins over the first-endpoint fallback, so
   multi-endpoint profiles still dispatch to the right binding
   for known upstream IPs.
3. **Port-based fallback on `:9000` / `:9440`** (lowest). A new
   `handleClickhouseNativeConn` mirrors `handlePostgresConn`:
   consult `ConnIndex` first, fall back to the first
   `clickhouse_native` endpoint in the device's profile, fall
   through to `wgRelay` when neither applies.

A single `HandleConn` in `clickhouse_native_runtime.go` services
all three. Every flow that reaches it terminates the native
protocol fully: parse Hello, swap placeholder credentials, dial
upstream, mediate Query/Data packets through the SQL rule matcher,
synthesise `ServerCodeException` on deny.

## Consequences

### Correctness

| concern                       | how it's handled                                                                                                                                                         |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| TLS handshake on `:9440`      | gateway terminates with an on-the-fly leaf minted off the gateway CA; agent trust comes from `SSL_CERT_FILE` pushdown by `clawpatrol run`.                              |
| Multi-host cluster            | hostname → one VIP → one endpoint binding; replicas resolved at dial time.                                                                                              |
| IP-literal upstream           | declared `hosts = ["172.17.0.1:9000"]` lands in `ConnIndex`; profile filter prevents cross-profile leakage.                                                              |
| Untracked upstream IP         | port-based fallback fires when a `clickhouse_native` endpoint exists in the profile; pure relay otherwise.                                                              |
| Compressed Data blocks        | opaque CityHash-discriminator probe (no LZ4/ZSTD decompression on the path); preserves agent's compression flag verbatim.                                               |
| Deny                          | `ServerCodeException` packet, error code 497 (`ACCESS_DENIED`), pump continues so a denied statement can't smuggle past an allowed one.                                  |

### Latency

- Steady-state per-query overhead is one VarInt decode of the
  Query packet plus rule evaluation. The query path in
  `chAgentToServer` runs at well under a millisecond on the loopback
  pipe used by the existing unit tests.
- Compressed Data blocks do **not** decompress — frames walk
  opaquely past the probe at near memcpy speed.
- Hello injection adds one round-trip of bytes the agent already
  was going to send; no extra RTT.
- Port-based fallback adds one map lookup vs. the prior
  `wgRelay` fast path; negligible.

### Implementation complexity

- The VIP path was already in place for SSH; ClickHouse just
  declares `RequiresVIP()` and `ConnRouteHosts()` and falls in.
- The direct-IP path reuses `ConnIndex` / `tryDirectIPConn`
  unchanged.
- The port-based fallback is ~30 lines mirroring
  `handlePostgresConn` and `firstPostgresEndpoint`.

The plugin's own runtime carries the protocol cost. That code
exists today and is exercised by the test suite in
`config/plugins/endpoints/clickhouse_native_test.go`.

### Failure modes and observability

- **Unknown packet code mid-session.** Future ClickHouse protocol
  additions surface as `unknown-client-packet` error events and
  tear the session down (rather than blindly forwarding a packet
  with unknown body length). Operators see this in the dashboard
  immediately; the fix is to add the packet code to
  `chAgentToServer`'s switch.
- **Probe slow-path timeout (`200ms`).** Headerless 1-byte
  packets (Ping = 4, Cancel = 3) immediately after a compressed
  Data block don't carry 24 more bytes; the probe relies on a
  read deadline to recognise the boundary. The deadline is
  generous over WG and well under any client-side Pong timeout
  we've seen.
- **VIP collision after CIDR rebinding.** Operators changing the
  VIP CIDR mid-deployment force a fresh allocation; the
  allocator drops persisted entries outside the new range
  (already handled in `dnsvip.load`).
- **Port collision with non-CH services on `:9000`.** The
  port-based fallback only fires when a `clickhouse_native`
  endpoint is declared in the device's profile. Profiles that
  declare none fall through to relay.

## Alternatives revisited and rejected

- **eBPF redirect.** Cross-platform reach is the project goal
  (Linux *and* macOS via Network Extension); cBPF/eBPF only
  carries weight on Linux and rules out the macOS path.
- **An HTTP-shaped front door for ClickHouse (`:8123` /
  `clickhouse_https`).** Useful and *separately implemented*,
  but it is not a substitute for native — `clickhouse-client`
  defaults to native and many production agents speak it.
- **Per-agent shim.** A library-level intercept (LD_PRELOAD,
  Python `sys.settrace`) inside the agent dodges the dispatch
  question but breaks the "agent doesn't know clawpatrol exists"
  contract and is infeasible for closed-source agents.

## Related code

- `main.go:tcpDispatch` — the forwarder switch.
- `main.go:handlePostgresConn` — the model
  `handleClickhouseNativeConn` follows.
- `main.go:handleVIPConn`, `main.go:tryDirectIPConn` — the other
  two dispatch surfaces.
- `config/plugins/endpoints/clickhouse_native.go` — schema and
  registration.
- `config/plugins/endpoints/clickhouse_native_runtime.go` —
  protocol termination.
- `dnsvip/dnsvip.go` — VIP allocation, DNS responder.

## Footnote on the "two approaches" framing

The inbox issue asks for a choice between "direct-IP (parse the
protocol)" and "VIP (TCP sniff only)". In the codebase those are
**not** mutually exclusive layers but the same protocol terminator
reached through two dispatch paths. The substantive ADR is
therefore *how dispatch picks the terminator*, not whether to
terminate the protocol at all. The terminator is settled — both
approaches converge on it.
