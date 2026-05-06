# Glossary

## The big picture

Claw Patrol is an HTTPS-and-friends [gateway](#gateway) that sits between
an [agent](#agent) (or any [device](#device) on its tunnel) and the
upstream services it talks to. The gateway is driven by a single HCL
global config that names [endpoints](#endpoint),
[credentials](#credential), [rules](#rule), and [approvers](#approver),
and groups them into [profiles](#profile) bound to specific devices.
Per-request, the gateway intercepts the connection ([MitM](#mitm) for
TLS, wire-protocol parsing for postgres), evaluates the matching rule,
optionally pauses for an approver, and stamps the real secret onto the
request before forwarding upstream. Everything user-extensible — new
upstream protocols, new auth shapes, new approval channels — is a
[plugin](#plugin) registered against `(kind, type)` and satisfying the
appropriate [runtime](#runtime) interface.

## Concepts

### Gateway

The Claw Patrol daemon. Terminates TLS via [MitM](#mitm), runs the
global config loader and the per-request dispatcher,
hosts the dashboard and HITL pool, and forwards traffic upstream after
secret injection. Configured by a top-level HCL file (`gateway.hcl`)
split into operational fields (listen address, CA dir, WireGuard
config) and the rest of the global config blocks.
See [Architecture](/docs/04-architecture/).

### Agent

A program whose outbound traffic is routed through the gateway —
typically an AI coding agent (Claude Code, Codex, OpenClaw) or a custom
script. The agent never holds real credentials; it sends
[placeholders](#placeholder) and the gateway swaps them at the wire.
"Agent" is the *who* of a request; [device](#device) is the *where it
came from* used by the global config.

### Device

A network peer the gateway recognizes, keyed by source IP — typically
a WireGuard tunnel address (`10.77.0.x`) or, on macOS, the IP the
Network Extension uses. A device is bound to exactly one
[profile](#profile), which determines which [endpoints](#endpoint)'
rules apply to its traffic (traffic to hosts outside the profile
falls through to `defaults.unknown_host`). The HCL
`device "<ip>" { ... }` block (see
[Configuration vocabulary](#configuration-vocabulary)) carries
per-device rule overrides.

### Endpoint

A typed upstream binding — a name, a protocol family
(`https` / `sql` / `k8s`), the host(s) it claims, and the
[credential](#credential)(s) the gateway should inject. Endpoints are
the unit a [device](#device)'s [profile](#profile) lists, and the unit
a [rule](#rule) attaches to. Built-in types: `https`, `kubernetes`,
`postgres`, `clickhouse_https`, `clickhouse_native`. See
[Configuration vocabulary](#configuration-vocabulary).

### Credential

A typed handle to a secret. The HCL block carries only how-to-inject
parameters (header name, cookie name, mTLS cert env var); the actual
secret bytes live in the gateway's [secret store](#secret-store) and
are fetched at injection time. Built-in shapes include `bearer_token`,
`cookie_token`, `header_token`, `mtls_credential`,
`postgres_credential`, `anthropic_manual_key`, and the OAuth variants.
See [Configuration vocabulary](#configuration-vocabulary).

### Rule

One policy decision targeting one or more [endpoints](#endpoint). Three
rule types — `http_rule`, `sql_rule`, `k8s_rule` — each constrained to
a matching endpoint family. A rule has a `match = { ... }` map (facets
depend on the rule type) and an [outcome](#outcome) — either a literal
`verdict` or an `approve = [...]` chain.

### Approver

An entity that arbitrates an `approve = [...]` chain stage. Built-in
types: `llm_approver` (Claude / GPT proctor that reads a
[`policy {}` block](#configuration-vocabulary) prompt) and
`human_approver` (Slack / dashboard, with optional N-of-N quorum).
Each approver type ships a [`ApproverRuntime`](#approverruntime)
implementation.

### Profile

A named list of [endpoints](#endpoint) attached to a [device](#device).
A profile names the endpoints whose [rules](#rule) apply to that
device's traffic — it is not an allowlist. Traffic to hosts not
covered by any profile endpoint falls through to
`defaults.unknown_host` (default: `passthrough`). Profiles are how
operators say "these are the endpoints I want to govern for this
device."

### Plugin

A `(kind, type)` extension — e.g. `(endpoint, https)`,
`(credential, bearer_token)`, `(approver, human_approver)`. A plugin
owns the body schema for its block kind, the in-memory record it
builds, optional rule lowering, HCL emit (for round-tripping), and an
optional [runtime](#runtime). Built-in plugins call `config.Register`
from their package's `init()`; `config/plugins/all` blank-imports them
all. See [Code-level vocabulary](#code-level-vocabulary).

### Outcome

The decision a matched [rule](#rule) carries: `verdict = "allow"`,
`verdict = "deny"`, or `approve = [...]` (an ordered list of
[approver](#approver) stages). On allow, the credential plugin's
runtime stamps the secret onto the forwarded request.

### Placeholder

A magic string an [agent](#agent) embeds in the auth slot when an
[endpoint](#endpoint) has multiple credentials wired through the
`credentials = [{ placeholder, credential }, ...]` shape. The gateway's
[`PlaceholderDetector`](#placeholderdetector) looks at the incoming
request, picks the matching credential, and substitutes the real
secret. The agent never holds the real key — only the placeholder.

### Secret store

The gateway-side source of secret bytes. Default backend: environment
variables, keyed by `CLAWPATROL_SECRET_<UPPER_NAME>` (with
`@/path/to/file` shorthand for reading PEM bundles off disk). mTLS
splits across `_CERT` / `_KEY` / `_CA`. Credential plugins call
`SecretStore.Get(name)` at injection time.

### MitM

"Man-in-the-middle" — the gateway's TLS interception strategy. It
forges a per-host certificate signed by the Claw Patrol CA, terminates
TLS itself, and re-establishes a fresh TLS connection upstream. The
[per-host cert](#per-host-cert) is generated on demand and cached.
This is also why the agent must trust the Claw Patrol CA. See
[Architecture › MitM TLS Interception](/docs/04-architecture/#mitm-tls-interception).

### Per-host cert

A short-lived (30-day) EC-P-256 leaf certificate generated on demand
for the SNI / CONNECT target, signed by the gateway CA, and cached in
an LRU (256 entries). The forged cert is what makes the
[MitM](#mitm) bridge work without the agent noticing.

### Auth offload

The gateway terminates upstream authentication on behalf of the
[agent](#agent), so the agent never participates in the handshake.
Today this is most visible for postgres: the gateway runs the SCRAM /
cleartext / trust dance against the upstream using the credential's
real `(user, password)` and synthesizes `AuthenticationOk` for the
agent. SCRAM is designed to defeat a passive password swap, so the
gateway has to *be* one of the peers — hence "offload" rather than
"forward."

## Configuration vocabulary

The HCL-level vocabulary an operator writes. Every named entity shares
**one flat namespace** — names are globally unique across all kinds —
and references are bare names (`endpoint = pg-writer`, never
`postgres.pg-writer`). The two-label `kind "type" "name" { ... }` shape
carries type information for schema dispatch; reference syntax doesn't
repeat it. See [`config/README.md`](../../config/README.md) for the
authoritative grammar.

### `defaults {}`

Singleton block. Global fallbacks: `unknown_host` (passthrough vs.
deny), `llm_fail_mode`, `llm_cache_ttl`, `human_timeout`,
`human_on_timeout`. Every plugin can read these from `BuildCtx` /
`ApproveRequest.Defaults`.

### `approver "<type>" "<name>" { ... }`

An [approver](#approver) entity. First label = type (`llm_approver` /
`human_approver`); second = bare name used in `approve = [...]`.

### `policy "<name>" { text = "..." }`

A reusable LLM proctor prompt. *Not* the global config — this is one
block within it. Referenced from `approve = [{ name, policy = my-policy
}, ...]` stages.

### `credential "<type>" "<name>" { ... }`

A [credential](#credential) entity. First label = type (`bearer_token`,
`mtls_credential`, `postgres_credential`, ...); second = bare name.

### `endpoint "<type>" "<name>" { ... }`

An [endpoint](#endpoint) entity. First label = endpoint type
(`https` / `kubernetes` / `postgres` / `clickhouse_*`); second = bare
name. Family-specific fields: `hosts` (for `https`), `host` + `database`
(for `postgres`), `server` + `ca_cert` (for `kubernetes`).

### `rule "<type>" "<name>" { ... }`

A [rule](#rule). First label = rule type (`http_rule` / `sql_rule` /
`k8s_rule`); second = bare name. Body carries `endpoint(s) =`,
`priority`, `match = { ... }`, and either `verdict` or `approve`.

### `profile "<name>" { endpoints = [...] }`

A [profile](#profile). Single-label block — bare name, plus an
endpoint-membership list.

### `device "<ip>" { rule ... ... { ... } }`

Per-device rule overrides — operator-edited from the dashboard's
per-device rule editor, spliced into `gateway.hcl` as standalone
blocks. Rules inside `device {}` reference the device's IP implicitly
and get a +1000 priority bump so they win against profile rules.

## Code-level vocabulary

Implementation terms that appear in package docs and code comments.

### Plugin

The Go-level realization of [plugin](#plugin) — a `config.Plugin`
struct registered via `config.Register`. Carries the decode struct
constructor (`New`), reference resolution (`Refs []RefSpec`),
`Validate`, `Build` (produces the canonical record), optional
`CompileRule` (rule plugins), `Emit` (HCL round-trip), and `Runtime`
(see below). See [`config/plugin.go`](../../config/plugin.go).

### Runtime

The request-time half of a [plugin](#plugin). Stored as `any` on the
`Plugin` struct and type-asserted by the dispatcher against one of the
interfaces below, picked by [kind](#configuration-vocabulary). A plugin
without a runtime is "schema-only" — the loader accepts it, but the
dispatcher returns `runtime.ErrUnsupported` if anything tries to use
it. `config/runtime/checker.go` validates the assertion at init time.

### `HTTPCredentialRuntime`

`InjectHTTP(ctx, req, sec) error` — the contract every HTTP-shaped
credential plugin satisfies. Mutates the outgoing `*http.Request`'s
headers (and possibly the URL, for cookie paths). Bearer / cookie /
header / mTLS-as-bearer / OAuth-with-bearer all live behind this one
hook.

### `PostgresCredentialRuntime`

`InjectPostgres(ctx, startup, sec) error` — swaps the agent's
StartupMessage password for the real one before the upstream connect.
Called once per session by the postgres wire-protocol front-end.

### `TLSCredentialRuntime`

`ConfigureUpstreamTLS(cfg, sec) error` — customizes the upstream
`*tls.Config` before dial. mTLS uses this to add `Certificates` and an
optional `RootCAs` pool; future shapes (pinned cert, ALPN twiddling)
fit the same hook.

### `ConnEndpointRuntime`

`HandleConn(ctx, ch *ConnHandle) error` — the runtime contract for
endpoints whose traffic doesn't fit `http.Request` (postgres today;
clickhouse_native and any future binary protocol slot in the same way).
Owns the inbound conn after TLS termination (where applicable), walks
the rule list with a family-appropriate `match.Request`, and forwards /
denies / pauses for approval per the matched rule's [outcome](#outcome).

### `ConnRouter`

`ConnRouteHosts() []string` — the optional interface an endpoint
plugin's body implements when its traffic arrives as raw conns rather
than via SNI. Returns the host[:port] tuples the endpoint claims; the
gateway resolves each via DNS once at config load and indexes
IP → endpoint for the [WG promiscuous forwarder](#wg-promiscuous-forwarder).

### `PlaceholderDetector`

`DetectPlaceholder(req, candidates) string` — the optional interface an
endpoint plugin's runtime implements so the multi-credential dispatch
logic can ask: "given this incoming request and these candidate
[placeholders](#placeholder), which one (if any) did the agent send?"
HTTPS scans the `Authorization` header; postgres reads the
StartupMessage password — putting the extraction logic on the
endpoint plugin keeps the dispatcher protocol-agnostic.

### `ApproverRuntime`

`Approve(ctx, req) (ApproveVerdict, error)` — the contract every
[approver](#approver) plugin's body implements. Built-in approvers
(dashboard, human, llm) implement it directly; out-of-tree approver
plugins ship their own type via the same interface.

### `ConnIndex`

The IP → endpoint map built by walking every endpoint whose body
implements [`ConnRouter`](#connrouter), resolving its declared hosts
once at config load. The [WG promiscuous forwarder](#wg-promiscuous-forwarder)
calls `ConnIndex.Lookup(dstIP)` to recover which endpoint(s) own a
given destination IP — multiple endpoints can share an IP (e.g.
`pg-writer` / `pg-readonly` against the same RDS host); the caller
filters by [profile](#profile) to pick the one the device should use.
See [`config/runtime/conn_route.go`](../../config/runtime/conn_route.go).

### WG promiscuous forwarder

The userspace WireGuard tunnel running in promiscuous mode — every
inbound packet is treated as "local source", which lets the gateway
accept SYNs to any dst IP/port without per-flow setup. Port 443 on
arbitrary IPs gets MitM'd; port 5432 routes through the postgres
[`ConnEndpointRuntime`](#connendpointruntime); other ports are relayed.
Backed by `boringtun` + `smoltcp`. See `WIREGUARD.md` and
`wireguard.go`.

### Auth offload

See [Auth offload](#auth-offload) under Concepts. In code, this is
the code path in `config/plugins/endpoints/postgres.go` that runs the
SCRAM / cleartext handshake against the upstream and synthesizes
`AuthenticationOk` for the agent.

### MitM / per-host cert

See [MitM](#mitm) and [per-host cert](#per-host-cert) under Concepts.
The interception bridge uses node:tls's
"loopback bridge" pattern — see
[Architecture › MitM TLS Interception](/docs/04-architecture/#mitm-tls-interception).
