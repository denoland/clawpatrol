# Plugin System

Claw Patrol's gateway policy is built from typed Go plugins registered at
startup. Plugins provide the schema and runtime behavior behind HCL blocks such
as `credential`, `endpoint`, `tunnel`, `rule`, and `approver`.

The source of truth for public configuration is `gateway.hcl`; see the
[HCL config reference](/docs/config-reference/) for generated field tables and
examples from the live plugin registry.

## Plugin kinds

| Kind | HCL syntax | Purpose |
| --- | --- | --- |
| Approver | `approver "<type>" "<name>" { ... }` | Decide or notify during approval chains. |
| Credential | `credential "<type>" "<name>" { ... }` | Define how secrets are loaded and injected. |
| Endpoint | `endpoint "<type>" "<name>" { ... }` | Handle an upstream service or protocol. |
| Tunnel | `tunnel "<type>" "<name>" { ... }` | Open or share an upstream tunnel used by endpoints. |
| Rule | `rule "<type>" "<name>" { ... }` | Attach policy to endpoint families. |

Each block's first label selects the registered plugin type; the second label is
the local name referenced by other blocks.

## Runtime flow

A request entering the gateway is matched against the compiled policy:

1. The connection or hostname selects an `endpoint`.
2. Endpoint-family `rule` blocks evaluate request details.
3. If the rule requires review, one or more `approver` stages run.
4. The endpoint asks its `credential` for the secret shape it needs.
5. If the endpoint references a `tunnel`, the tunnel manager opens or reuses the
   configured tunnel before dialing upstream.
6. The endpoint runtime injects credentials and forwards the request.

Plugins are typed Go structs. Their HCL tags define accepted fields, and their
runtime interfaces define behavior for HTTP, WebSocket payload rewriting,
PostgreSQL, SSH, ClickHouse, Kubernetes, tunnels, and approval flows.

## Registered plugin inventory

Current built-in plugin types include:

### Approvers

- `human_approver`
- `llm_approver`

### Credentials

- `anthropic_manual_key`
- `anthropic_oauth_subscription`
- `aws_eks_credential`
- `bearer_token`
- `clickhouse_credential`
- `cookie_token`
- `discord_bot_token`
- `gemini_api_key`
- `github_oauth`
- `header_token`
- `mtls_credential`
- `notion_oauth`
- `openai_codex_oauth`
- `postgres_credential`
- `slack_tokens`
- `ssh`
- `telegram_bot_token`

### Endpoints

- `clickhouse_https`
- `clickhouse_native`
- `https`
- `kubernetes`
- `openai_codex_https`
- `postgres`
- `ssh`

### Tunnels

- `kubernetes_port_forward`
- `local_command`
- `ssh_port_forward`
- `tailscale`

The generated [HCL config reference](/docs/config-reference/) lists exact fields
for each type.

## Credentials and secret sources

Credential plugins describe how an endpoint obtains real secret material. At
runtime, secrets can come from OAuth-backed gateway storage, manual dashboard
entries, or environment fallbacks.

Environment fallback names are derived from the credential block name:

```bash
CLAWPATROL_SECRET_<NAME>
```

Hyphens in `<NAME>` become underscores and the name is uppercased. For mTLS
credentials, Claw Patrol also recognizes:

```bash
CLAWPATROL_SECRET_<NAME>_CERT
CLAWPATROL_SECRET_<NAME>_KEY
CLAWPATROL_SECRET_<NAME>_CA
```

These values may be inline material or `@/path/to/file` references, depending
on the credential type.

## Endpoints

Endpoint plugins own protocol-specific routing and injection. Examples:

- `https` handles generic HTTPS targets and header/cookie-style credentials.
- `openai_codex_https` handles OpenAI Codex/ChatGPT traffic and OAuth-derived
  credentials.
- `postgres`, `clickhouse_native`, and `clickhouse_https` handle database
  protocols and SQL-aware request facets.
- `ssh` handles SSH sessions, exec, port forwarding, and SFTP through a stable
  virtual-IP path.
- `kubernetes` handles Kubernetes API access with configured credentials.

Endpoints can expose facets for rule matching and dashboard analytics. Rules
attach to endpoint families rather than to arbitrary traffic.

## Tunnels

Tunnel plugins create reusable upstream paths for endpoints. An endpoint can
reference a tunnel with `tunnel = <name>` in HCL.

Built-in tunnel types cover common private-network access patterns:

- `local_command` — start a local helper command that exposes a listener.
- `ssh_port_forward` — dial through an SSH bastion.
- `kubernetes_port_forward` — run `kubectl port-forward` to a pod, service, or
  generated helper pod.
- `tailscale` — dial upstream through an embedded tsnet client.

Tunnels can be shared according to their `share` mode, kept alive with
`keepalive`, and chained through another tunnel via `via` when supported.

## Approvers and rules

Approvers implement approval stages used by rules. The built-in human approver
routes decisions through configured human-in-the-loop targets, while the LLM
approver asks a model to judge whether a request should be allowed according to
policy text.

Rules are endpoint-family specific. They extract facts from requests — HTTP
metadata, SQL operations, SSH activity, Kubernetes operations, and similar
facets — and return allow/deny/review decisions.

## Developing built-ins

Built-in plugins live under `config/plugins/`. A plugin registers itself with
`config.Register` from an `init` path imported by `config/plugins/all`.

Relevant source areas:

| Path | Purpose |
| --- | --- |
| `config/framework.go` | Shared HCL/framework field handling. |
| `config/runtime/` | Runtime interfaces used by endpoint, credential, tunnel, and approver plugins. |
| `config/plugins/credentials/` | Built-in credential plugin schemas/runtimes. |
| `config/plugins/endpoints/` | Built-in endpoint plugin schemas/runtimes. |
| `config/plugins/tunnels/` | Built-in tunnel plugin schemas/runtimes. |
| `config/plugins/approvers/` | Built-in approvers. |
| `tools/docgen/` | Generates `site/doc/config-reference.md` from the live registry. |

After changing plugin schemas, regenerate and verify the public reference:

```bash
go generate ./config/plugins/all
go test ./tools/docgen ./tools/docgen/internal/render
```
