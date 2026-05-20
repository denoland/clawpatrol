# Glossary

## The big picture

Claw Patrol sits between an [agent](#agent) and the upstream services
it talks to. Operators describe the system with [endpoints](#endpoint),
[credentials](#credential), [rules](#rule), [approvers](#approver), and
[profiles](#profile). This page defines those terms; see
[Architecture](/docs/architecture/) for traffic flow and
[Config Reference](/docs/config-reference/) for HCL fields.

## Concepts

### Gateway

The Claw Patrol daemon. It loads config, hosts the operator UI, applies
policy, injects real credentials, and forwards allowed traffic upstream.
See [Architecture](/docs/architecture/) for the gateway’s position in a
deployment.

### Agent

A program whose outbound traffic is routed through the gateway —
typically an AI coding agent (Claude Code, Codex, OpenClaw) or a custom
script. The agent never holds real credentials; it sends
[placeholders](#placeholder) and the gateway swaps them at the wire.
"Agent" is the *who* of a request; [device](#device) is the *where it
came from* used by the global config.

### Device

A machine whose traffic is routed through the gateway. The gateway
recognizes a device as the source identity for a request, and operators
assign each device one [profile](#profile).

### Endpoint

A typed network target — a name, a protocol family
(`https` / `sql` / `k8s`), and the host(s) it claims. Endpoints are
pure network targets: hosts plus protocol-family connection parameters,
nothing more. The unit a [rule](#rule) attaches to. See
[Config Reference](/docs/config-reference/) for endpoint schemas.

### Credential

A typed handle to a secret for one or more [endpoints](#endpoint). The
config block describes where the secret should be injected; the secret
bytes stay in the gateway’s [secret store](#secret-store). See
[Config Reference](/docs/config-reference/) for credential schemas.

### Action

One unit of agent work the gateway sees and applies policy to — one
HTTP call, one SQL query, one `kubectl` invocation, one SSH command.
Each action targets an [endpoint](#endpoint), is gated by the matching
[rule](#rule)'s [outcome](#outcome), and surfaces in the dashboard’s
live request feed. "Action" is the operator-visible concept of "the
thing the agent did."

### Rule

One policy decision targeting one or more [endpoints](#endpoint). A
rule has a CEL [`condition`](#cel-condition) string that matches against
the [facets](#facet) of the rule’s protocol family (inferred from its
endpoints), an optional `credential` predicate, and an [outcome](#outcome)
— either a literal `verdict` or an `approve = [...]` chain. See
[Rules](/docs/rules/) for family-specific matching and examples.

### Facet

A single named matchable property exposed to a [rule](#rule)'s CEL
[`condition`](#cel-condition), such as the HTTP method, SQL tables, or
Kubernetes resource. Each protocol family exposes its own facets. See
[Rules](/docs/rules/) for the full list.

### CEL condition

The boolean expression a [rule](#rule)'s `condition = "..."` field
carries. CEL ([Common Expression Language](https://github.com/google/cel-spec))
is evaluated against the [facets](#facet) of the rule’s inferred family.
An absent or empty `condition` matches every request the rule’s
endpoints see.

### Approver

An entity that arbitrates an `approve = [...]` chain stage. Built-in
types: `llm_approver` (Claude / GPT proctor that reads a
`policy` prompt) and
`human_approver` (Slack / dashboard, with optional N-of-N quorum).

### Profile

A named list of [credentials](#credential) attached to a
[device](#device). Endpoint membership follows the credentials in the
profile, so profiles are how operators say "these are the secrets I want
this device to wield."

### Plugin

A `(kind, type)` extension — e.g. `(endpoint, https)`,
`(credential, bearer_token)`, `(approver, human_approver)`. Plugins add
new config block types and the behavior behind them. See
[Plugins](/docs/plugins/).

### Outcome

The decision a matched [rule](#rule) carries: `verdict = "allow"`,
`verdict = "deny"`, or `approve = [...]` (an ordered list of
[approver](#approver) stages). On allow, the credential plugin’s
runtime stamps the secret onto the forwarded request.

### Placeholder

A magic string an [agent](#agent) embeds in the auth slot when its
[profile](#profile) wields more than one [credential](#credential) at
the same [endpoint](#endpoint). The profile’s credentials list mixes
bare-name entries with inline `{ placeholder = "PH_...", credential =
name }` objects that name the discriminator for each ambiguous
credential; the gateway looks at the incoming request, picks the
matching credential, and substitutes the real secret. Placeholders
live on the profile (not the credential) because the ambiguity exists
only when one identity actively uses multiple credentials at one
endpoint. The agent never holds the real key — only the placeholder.

### Secret store

The gateway-side source of secret bytes. Default backend: environment
variables, keyed by `CLAWPATROL_SECRET_<UPPER_NAME>` (with
`@/path/to/file` shorthand for reading PEM bundles off disk).

### MitM

"Man-in-the-middle" — the gateway’s TLS interception strategy. It
allows the gateway to inspect and authorize encrypted protocol traffic
before forwarding it upstream. See
[Architecture › MitM TLS Interception](/docs/architecture/#mitm-tls-interception).

### Per-host cert

A certificate the gateway generates for a specific upstream host during
[MitM](#mitm) TLS interception.

### Auth offload

The gateway performs an upstream authentication handshake on behalf of
the [agent](#agent), using the real credential while keeping that
credential out of the agent process.

## Config mapping

The HCL file is where these concepts are declared. This section only
maps concepts to their config homes; use [Config Reference](/docs/config-reference/)
for exact fields, types, and examples.

| Concept | Config home |
|---------|-------------|
| Gateway operations | Top-level fields such as `listen`, `public_url`, WireGuard settings, and policy fallbacks. |
| Endpoint | `endpoint "<type>" "<name>" { ... }` blocks. |
| Credential | `credential "<type>" "<name>" { ... }` blocks plus secret-store bytes. |
| Rule | `rule "<name>" { ... }` blocks; see [Rules](/docs/rules/) for matching semantics. |
| Approver | `approver "<type>" "<name>" { ... }` blocks. |
| Policy text | `policy "<name>" { text = ... }` blocks referenced by LLM approvers. |
| Profile | `profile "<name>" { credentials = [...] }` blocks assigned to devices. |
| Plugin | `plugin "<name>" { source = ... }` blocks that register extra endpoint, credential, approver, rule, or tunnel types. |

<!-- Implementation-level vocabulary (Plugin, Runtime, the
HTTP/Postgres/TLS/Conn runtime interfaces, ConnIndex, the WG
promiscuous forwarder, etc.) lives in the repo’s internal
doc/code-vocabulary.md, not here. -->
