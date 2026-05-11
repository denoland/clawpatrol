# Code-level vocabulary

Implementation terms that appear in package docs and code comments.
For user-facing concepts (gateway, agent, endpoint, rule, profile,
credential, approver, mitm, ...) see the public
[glossary](/docs/glossary/).

## Plugin

The Go-level realization of a plugin — a `config.Plugin` struct
registered via `config.Register`. Carries the decode struct
constructor (`New`), reference resolution (`Refs []RefSpec`),
`Validate`, `Build` (produces the canonical record), optional
`CompileRule` (rule plugins), `Emit` (HCL round-trip), and `Runtime`
(see below). See [`config/plugin.go`](../config/plugin.go).

## Runtime

The request-time half of a plugin. Stored as `any` on the `Plugin`
struct and type-asserted by the dispatcher against one of the
interfaces below, picked by kind. A plugin without a runtime is
"schema-only" — the loader accepts it, but the dispatcher returns
`runtime.ErrUnsupported` if anything tries to use it.
`config/runtime/checker.go` validates the assertion at init time.

## `HTTPCredentialRuntime`

`InjectHTTP(ctx, req, sec) error` — the contract every HTTP-shaped
credential plugin satisfies. Mutates the outgoing `*http.Request`'s
headers (and possibly the URL, for cookie paths). Bearer / cookie /
header / mTLS-as-bearer / OAuth-with-bearer all live behind this one
hook.

## `PostgresCredentialRuntime`

`InjectPostgres(ctx, startup, sec) error` — swaps the agent's
StartupMessage password for the real one before the upstream connect.
Called once per session by the postgres wire-protocol front-end.

## `TLSCredentialRuntime`

`ConfigureUpstreamTLS(cfg, sec) error` — customizes the upstream
`*tls.Config` before dial. mTLS uses this to add `Certificates` and an
optional `RootCAs` pool; future shapes (pinned cert, ALPN twiddling)
fit the same hook.

## `ConnEndpointRuntime`

`HandleConn(ctx, ch *ConnHandle) error` — the runtime contract for
endpoints whose traffic doesn't fit `http.Request` (postgres today;
clickhouse_native and any future binary protocol slot in the same way).
Owns the inbound conn after TLS termination (where applicable), walks
the rule list with a family-appropriate `match.Request`, and forwards /
denies / pauses for approval per the matched rule's outcome.

## `ConnRouter`

`ConnRouteHosts() []string` — the optional interface an endpoint
plugin's body implements when its traffic arrives as raw conns rather
than via SNI. Returns the host[:port] tuples the endpoint claims; the
gateway resolves each via DNS once at config load and indexes
IP → endpoint for the [WG promiscuous forwarder](#wg-promiscuous-forwarder).

## `PlaceholderDetector`

`DetectPlaceholder(req, candidates) string` — the optional interface an
endpoint plugin's runtime implements so the multi-credential dispatch
logic can ask: "given this incoming request and these candidate
placeholders, which one (if any) did the agent send?" HTTPS scans the
`Authorization` header; postgres reads the StartupMessage password —
putting the extraction logic on the endpoint plugin keeps the
dispatcher protocol-agnostic.

## `ApproverRuntime`

`Approve(ctx, req) (ApproveVerdict, error)` — the contract every
approver plugin's body implements. Built-in approvers (dashboard,
human, llm) implement it directly; out-of-tree approver plugins ship
their own type via the same interface.

## `ConnIndex`

The IP → endpoint map built by walking every endpoint whose body
implements [`ConnRouter`](#connrouter), resolving its declared hosts
once at config load. The [WG promiscuous forwarder](#wg-promiscuous-forwarder)
calls `ConnIndex.Lookup(dstIP)` to recover which endpoint(s) own a
given destination IP — multiple endpoints can share an IP (e.g.
`pg-writer` / `pg-readonly` against the same RDS host); the caller
filters by profile to pick the one the device should use. See
[`config/runtime/conn_route.go`](../config/runtime/conn_route.go).

## WG promiscuous forwarder

The userspace WireGuard tunnel running in promiscuous mode — every
inbound packet is treated as "local source", which lets the gateway
accept SYNs to any dst IP/port without per-flow setup. Port 443 on
arbitrary IPs gets MitM'd; port 5432 routes through the postgres
[`ConnEndpointRuntime`](#connendpointruntime); other ports are relayed.
Backed by `boringtun` + `smoltcp`. See [`wireguard.md`](wireguard.md)
and [`wireguard.go`](../wireguard.go).

## Auth offload

The code path in `config/plugins/endpoints/postgres.go` that runs the
SCRAM / cleartext handshake against the upstream and synthesizes
`AuthenticationOk` for the agent — so the agent never participates in
the upstream auth handshake. (User-facing description in the public
[glossary](/docs/glossary/#auth-offload).)

## MitM / per-host cert

The interception bridge uses node:tls's "loopback bridge" pattern.
See the public glossary's [MitM](/docs/glossary/#mitm) and
[per-host cert](/docs/glossary/#per-host-cert) entries, and
[Architecture › MitM TLS Interception](/docs/architecture/#mitm-tls-interception).
