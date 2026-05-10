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
appropriate runtime interface.

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

### Action

One unit of agent work the gateway sees and applies policy to — one
HTTP call, one SQL query, one `kubectl` invocation, one SSH command.
Each action targets an [endpoint](#endpoint), is gated by the matching
[rule](#rule)'s [outcome](#outcome), and surfaces in the dashboard's
live request feed (record kinds: `http`, `sql`, `k8s`, `ssh`) with its
own detail page. "Action" is the operator-visible concept of "the
thing the agent did."

### Rule

One policy decision targeting one or more [endpoints](#endpoint). Three
rule types — `http_rule`, `sql_rule`, `k8s_rule` — each constrained to
a matching endpoint family. A rule has a `match = { ... }` map of
[facets](#facet) (the set depends on the rule type) and an
[outcome](#outcome) — either a literal `verdict` or an `approve = [...]`
chain.

### Facet

A single named matchable property inside a [rule](#rule)'s
`match { ... }` block. Each rule family exposes its own facet set:
`http_rule` carries `method` / `path` / `query` / `headers` /
`body_json` / `body_contains` / `credential`; `sql_rule` carries
`verb` / `tables` / `function` / `statement` / `statement_regex` /
`credential`; `k8s_rule` carries `resource` / `verb` / `namespace` /
`name` / `params` / `credential`. Per-facet semantics vary — list
values are any-of, a `!`-prefix on a string negates it, and individual
facets are glob, PCRE, or exact match.

### Approver

An entity that arbitrates an `approve = [...]` chain stage. Built-in
types: `llm_approver` (Claude / GPT proctor that reads a
[`policy {}` block](#configuration-vocabulary) prompt) and
`human_approver` (Slack / dashboard, with optional N-of-N quorum).

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
`credentials = [{ placeholder, credential }, ...]` shape. The gateway
looks at the incoming request, picks the matching credential, and
substitutes the real secret. The agent never holds the real key —
only the placeholder.

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

<!-- Implementation-level vocabulary (Plugin, Runtime, the
HTTP/Postgres/TLS/Conn runtime interfaces, ConnIndex, the WG
promiscuous forwarder, etc.) lives in the repo's internal
doc/code-vocabulary.md, not here. -->

