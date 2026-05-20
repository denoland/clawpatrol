# Config Reference

A clawpatrol gateway config mixes **operational** fields (top-level
plumbing) with **policy** blocks. Operational fields are top-level
attributes; policy blocks (`approver`, `credential`, `tunnel`, `endpoint`, `rule`)
dispatch to a plugin chosen by the block's first label.

## How to read this page

Each block section lists the attributes the loader accepts, with:

- **Type** — the HCL value type. `string`, `bool`, `int` are scalar
  literals; `[]string` is a list of strings; `ref(<kind>)` is a
  typed reference to another block (`<type>.<name>` for
  two-label kinds like `credential = bearer_token.github`,
  `<kind>.<name>` for one-label kinds like `policy = policy.no-pii`);
  `[]ref(<kind>)` is a list of such references; nested blocks have
  their shape described inline.
- **Required** — `yes` if the loader rejects the block when the
  attribute is missing.

Plugin-dispatched kinds (`approver`, `credential`, `tunnel`, `endpoint`, `rule`)
list one subsection per registered type.

## Top-level fields

Every singleton gateway attribute — listen addresses, paths, control-plane joining, WireGuard endpoint, and policy fallbacks — is set directly at the top of `gateway.hcl`. Labeled blocks (`policy`, `profile`, `approver`, `credential`, `endpoint`, `rule`, `tunnel`) are documented in their own sections.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `listen` | `string` | no | The main gateway bind address for proxied agent traffic and dashboard HTTP. Defaults to the runtime's standard listen address when unset. |
| `info_listen` | `string` | no | The optional diagnostics / info listener bind address. Leave unset to use the runtime default. |
| `public_url` | `string` | no | The canonical externally reachable gateway URL used for generated control-plane links such as WireGuard join targets and async HITL status URLs. Runtime code normalizes away trailing slashes. |
| `admin_email` | `string` | no | The operator contact shown in generated onboarding and status surfaces. |
| `state_dir` | `string` | no | The directory holding clawpatrol.db (and anything else a plugin persists to disk under it). Defaults to ${HOME}/.clawpatrol when unset. |
| `resolver` | `string` | no | The DNS resolver address the gateway should use for upstream lookups when the runtime needs an explicit resolver. |
| `log_path` | `string` | no | An optional file path for gateway log output. |
| `dashboard_operators` | `[]string` | no | Allowlists tailnet logins permitted to use the dashboard / management API in tailscale-control mode. Each entry is either an exact login ("alice@example.com") or a domain wildcard ("*@example.com"). Tagged devices (whose whois login is the tag name, not a user email) never match a wildcard entry — agents on the tailnet can never bypass the gate through this path. Empty / unset → tailnet-allowlist auth is disabled and the stored root password is the only way in. In WireGuard / proxy control mode this field is logged once as a no-op and ignored. |
| `dashboard_session_ttl` | `string` | no | How long a dashboard login session stays valid after the operator types the password. Format accepts time.ParseDuration strings ("24h", "30m", "168h"). Empty / unset → defaults to 24h. Bumping this trades log-in frequency against blast radius if a session cookie leaks. Rotating the root password (`--set-dashboard-password` or the web form) revokes every existing session immediately regardless of TTL. |
| `telemetry` | `bool` | no | Opts in/out of the update-checker / anonymous usage ping (doc/telemetry.md). nil = default on; explicit `telemetry = false` silences the goroutine. Env vars CLAWPATROL_TELEMETRY=0 and DO_NOT_TRACK=1 also work. |
| `session_keep` | `string` | no | The hard retention floor for the sessions table. Sessions whose last_at is older than this get deleted by the background sweeper. Sessions can revive on new activity at any time, so there's no "closed but kept" intermediate state — only last_at matters. Default 720h (30d), "0" / "off" disables. Format accepts time.ParseDuration strings ("30m", "168h", etc.). |
| `authkey` | `string` | no | The Tailscale auth key used to start the embedded tsnet node. Setting it selects Tailscale control mode. |
| `control_url` | `string` | no | The Tailscale control-plane URL for tsnet. Defaults to Tailscale's hosted control plane when unset. |
| `hostname` | `string` | no | The device name requested for the embedded tsnet node. |
| `control` | `string` | no | Selects the gateway control transport. Supported values depend on the build/runtime mode; leave unset for the default. |
| `funnel` | `bool` | no | Enables Tailscale Funnel on the embedded tsnet node so that join, webhook, and CA endpoints are reachable from the internet via the node's HTTPS cert domain (e.g. clawpatrol-gateway.ts.net:443). Only meaningful in tsnet control mode (authkey set). Tailscale's HTTPS must be enabled for the tailnet; if public_url is unset the gateway will derive it from the tsnet cert domain at startup. |
| `oauth_client_id` | `string` | no | The OAuth client id used by control-plane integrations that need OAuth enrollment. |
| `oauth_client_secret` | `string` | no | The OAuth client secret paired with oauth_client_id. |
| `tailscale_tags` | `[]string` | no | The Tailscale device-tag list applied to keys the gateway mints for onboarded clients (`tag:client` etc.). Tailscale-only — ignored in WireGuard mode. |
| `wg_interface` | `string` | no | The WireGuard interface name the gateway creates or manages in WireGuard control mode. |
| `wg_endpoint` | `string` | no | The WireGuard client dial target, usually "host:port". If the host is omitted or wildcard, onboarding uses public_url's host with this port. |
| `wg_server_pub` | `string` | no | The WireGuard server public key advertised to onboarded clients. Normally derived from gateway state. |
| `wg_subnet_cidr` | `string` | no | The private subnet assigned to WireGuard clients. |
| `unknown_host` | `string` | no | Controls traffic whose destination does not match any endpoint. "passthrough" relays it; "deny" closes it. |
| `llm_fail_mode` | `string` | no | Controls requests guarded by LLM approvers when the model call errors or times out. "closed" denies; "open" allows. |
| `llm_cache_ttl` | `int` | no | The LLM decision cache lifetime in seconds. |
| `human_timeout` | `int` | no | The default human-approval timeout in seconds. |
| `human_on_timeout` | `string` | no | The default outcome when a human approver does not answer before timeout. Supported values are "deny" and "allow". |
| `plugin` | `block` | no | Lists every `plugin "<name>" { source = "..." }` block at the top of the file. The loader spawns each subprocess (and registers its declared types) before running pass-1 symbol building, so plugin-supplied (kind, type) pairs are available by the time policy blocks are dispatched. |

## `policy "<name>" { ... }`

Defines a named, reusable chunk of policy prose that
`llm_approver` blocks reference by name. The single `text` attribute
is typically a heredoc.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `text` | `string` | yes | The policy prose passed to llm_approver blocks. |

```hcl
policy "example" {
  text = <<-EOT
    Example policy text.
  EOT
}
```

## `profile "<name>" { ... }`

Names a set of credentials. Profiles bind to dashboard owners; an owner's profile determines which credentials — and, transitively via each credential's `endpoint` / `endpoints` binding, which endpoints — their gateway requests can reach. Rules ride along automatically because they're attached to endpoints.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `credentials` | `[]credential` | yes | Bare-name credential references, or `{ credential = name, <disambiguator> = "..." }` object entries for multi-credential dispatch (e.g. `placeholder` for header-token credentials). |
| `hitl_async_grants` | `bool` | no | Explicit opt-in for agent-aware async HITL retry grants on this profile. Async behavior still also requires an approver with `async_grant.enabled = true`. |

```hcl
profile "default" {
  credentials       = [bearer_token.github, postgres_credential.postgres-prod]
  hitl_async_grants = true
}
```

## `approver` blocks

Block syntax: `approver "<type>" "<name>" { ... }`

Registered types: [`human_approver`](#approver-humanapprover), [`llm_approver`](#approver-llmapprover).

### `approver "human_approver" "<name>"`

Targets one channel. Timeout / require_approvers
override the global defaults block on a per-approver basis.

Credential references a credential whose body satisfies HITLNotifier
(slack_tokens today; future Discord / Telegram / SMTP credentials).
Leave empty for a dashboard-only approver (no channel notification;
operator clicks approve/deny on the dashboard).

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `channel` | `string` | yes | The destination channel, chat id, or equivalent notifier-specific target. |
| `credential` | `ref(credential)` | no | References the notifier credential used to post approval requests. Leave empty for dashboard-only approval. |
| `timeout` | `int` | no | Overrides the gateway's human_timeout for this approver, in seconds. |
| `require_approvers` | `int` | no | The number of separate human approvals required before the request is allowed. |
| `sync_wait_timeout` | `string` | no | The HTTP hold budget before an async-capable HITL request returns 202 and moves to polling/retry-grant mode. |
| `async_grant` | `block` | no | Configures v1 HITL async retry grants for this approver. The nested block must set enabled = true, and the active profile must also set hitl_async_grants = true, before async behavior is effective. |
| `interactive` | `bool` | no | Toggles in-channel approve/deny buttons. Requires the referenced credential's signing_secret slot pasted via the dashboard AND Slack's Interactivity URL pointed at the gateway. Default false: message includes only an "Open dashboard" link. |
| `classifier` | `ref(approver)` | no | Optionally references an llm_approver by name. When set, the approver calls the classifier's Summarize method before posting the HITL notification, enriching the Slack card with classification metadata. Classifier failures are non-fatal — the generic card is used as fallback. |
| `message` | `string` | no | An optional Go-template-style string with {{var}} placeholders. When set, the expanded text replaces the default section body in the Slack (or other notifier) card. Supported vars mirror the CEL facet namespace: {{http.method}}, {{http.path}}, {{k8s.verb}}, {{sql.tables}}, {{body_json.ticket}}, {{profile}}, {{endpoint}}, {{reason}}, etc. Classifier (if also set) still runs; Message takes display precedence. |

**Nested block `async_grant {}`:**

The optional nested `async_grant { ... }`
block shared by async-capable HITL approvers. It is schema-only here;
runtime execution lives in the gateway and endpoint layers.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `enabled` | `bool` | no | Explicitly opts this approver into async retry-grant mode. The active profile must also set hitl_async_grants = true. |
| `approval_ttl` | `string` | no | Human approval lifetime after the original sync wait falls back to a 202 response. |
| `approved_retry_ttl` | `string` | no | Post-approval retry grant lifetime for the client to retry. |
| `fingerprint_body` | `string` | no | Request-body fingerprinting mode. V1 supports only "raw". |
| `max_body_bytes` | `int` | no | Maximum request body size eligible for async raw-body fingerprinting. |

```hcl
approver "human_approver" "example" {
  channel = "#approvals"
}
```

### `approver "llm_approver" "<name>"`

Carries the model + the credential used to authenticate
the call to the model API + the policy text the model judges
against. Inline `policy` is a bare-name reference to a `policy
"<name>" { text = ... }` block — operator declares the prompt once
and reuses across multiple judges.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `model` | `string` | yes | The model id used for policy judgment, such as a claude-*, gpt-*, or o*-prefixed model. |
| `credential` | `ref(credential)` | yes | References the HTTP credential used to authenticate the model API call. |
| `policy` | `ref(policy)` | no | References a policy block containing the text the model judges requests against. |

```hcl
approver "llm_approver" "example" {
  model = "claude-haiku-4-5-20251001"
  credential = bearer_token.example
}
```

## `credential` blocks

Block syntax: `credential "<type>" "<name>" { ... }`

Registered types: [`anthropic_manual_key`](#credential-anthropicmanualkey), [`anthropic_oauth_subscription`](#credential-anthropicoauthsubscription), [`aws_credential`](#credential-awscredential), [`bearer_token`](#credential-bearertoken), [`clickhouse_credential`](#credential-clickhousecredential), [`cookie_token`](#credential-cookietoken), [`discord_bot_token`](#credential-discordbottoken), [`gemini_api_key`](#credential-geminiapikey), [`github_oauth`](#credential-githuboauth), [`google_gke_credential`](#credential-googlegkecredential), [`header_token`](#credential-headertoken), [`mtls_credential`](#credential-mtlscredential), [`notion_mcp_oauth`](#credential-notionmcpoauth), [`notion_oauth`](#credential-notionoauth), [`openai_codex_oauth`](#credential-openaicodexoauth), [`postgres_credential`](#credential-postgrescredential), [`slack_tokens`](#credential-slacktokens), [`ssh_key`](#credential-sshkey), [`tailscale_auth`](#credential-tailscaleauth), [`telegram_bot_token`](#credential-telegrambottoken).

### `credential "anthropic_manual_key" "<name>"`

_No configurable attributes._

```hcl
credential "anthropic_manual_key" "example" {}
```

### `credential "anthropic_oauth_subscription" "<name>"`

_No configurable attributes._

```hcl
credential "anthropic_oauth_subscription" "example" {}
```

### `credential "aws_credential" "<name>"`

Schema is intentionally empty: access key id and secret access key
(and optional session token) live in the secret store as named
slots, filled via the dashboard or CLAWPATROL_SECRET_<NAME>_<SLOT>
env vars. Cluster + region come from the kubernetes endpoint at
request time.

_No configurable attributes._

```hcl
credential "aws_credential" "example" {}
```

### `credential "bearer_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `idempotency_key` | `bool` | no | Stamps a deterministic Idempotency-Key header on non-GET/HEAD HTTP requests when the agent did not provide one. |

```hcl
credential "bearer_token" "example" {}
```

### `credential "clickhouse_credential" "<name>"`

Database, when set, is the discriminator the dispatcher uses to
pick this credential when several clickhouse_credential blocks
bind the same endpoint(s). At request time the gateway reads the
agent-declared database off the wire and picks the credential
whose `database` matches; an unset `database` field is the
catchall (one allowed per (profile, endpoint)).

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `user` | `string` | no | The upstream ClickHouse user the gateway injects. |
| `database` | `string` | no | Limits this credential to ClickHouse requests for that database. Empty acts as the catchall. |

```hcl
credential "clickhouse_credential" "example" {}
```

### `credential "cookie_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `cookie_name` | `string` | no | The HTTP cookie name that receives the secret value. |

```hcl
credential "cookie_token" "example" {}
```

### `credential "discord_bot_token" "<name>"`

Injects Discord bot tokens for REST and Gateway SDK traffic.

_No configurable attributes._

```hcl
credential "discord_bot_token" "example" {}
```

### `credential "gemini_api_key" "<name>"`

_No configurable attributes._

```hcl
credential "gemini_api_key" "example" {}
```

### `credential "github_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "github_oauth" "example" {}
```

### `credential "google_gke_credential" "<name>"`

_No configurable attributes._

```hcl
credential "google_gke_credential" "example" {}
```

### `credential "header_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `header` | `string` | yes | The HTTP header name to overwrite with the secret value. |
| `prefix` | `string` | no | Prepended to the secret before injection, for schemes such as "Bearer " or "Token ". |

```hcl
credential "header_token" "example" {
  header = "X-API-Key"
}
```

### `credential "mtls_credential" "<name>"`

_No configurable attributes._

```hcl
credential "mtls_credential" "example" {}
```

### `credential "notion_mcp_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "notion_mcp_oauth" "example" {}
```

### `credential "notion_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "notion_oauth" "example" {}
```

### `credential "openai_codex_oauth" "<name>"`

_No configurable attributes._

```hcl
credential "openai_codex_oauth" "example" {}
```

### `credential "postgres_credential" "<name>"`

Database, when set, is the discriminator the dispatcher uses to
pick this credential when several postgres_credential blocks bind
the same endpoint(s). At request time the gateway reads the
agent-declared database off the StartupMessage and picks the
credential whose `database` matches; an unset `database` field is
the catchall (one allowed per (profile, endpoint)).

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `user` | `string` | no | The upstream Postgres role the gateway authenticates as. |
| `database` | `string` | no | Limits this credential to sessions whose StartupMessage declares the same database. Empty acts as the catchall. |

```hcl
credential "postgres_credential" "example" {}
```

### `credential "slack_tokens" "<name>"`

_No configurable attributes._

```hcl
credential "slack_tokens" "example" {}
```

### `credential "ssh_key" "<name>"`

_No configurable attributes._

```hcl
credential "ssh_key" "example" {}
```

### `credential "tailscale_auth" "<name>"`

Has no operator-facing fields — there is
nothing to paste. Per-tailnet selection (control_url, tags) lives
on the tunnel block instead.

_No configurable attributes._

```hcl
credential "tailscale_auth" "example" {}
```

### `credential "telegram_bot_token" "<name>"`

_No configurable attributes._

```hcl
credential "telegram_bot_token" "example" {}
```

## `endpoint` blocks

Block syntax: `endpoint "<type>" "<name>" { ... }`

Registered types: [`clickhouse_https`](#endpoint-clickhousehttps), [`clickhouse_native`](#endpoint-clickhousenative), [`https`](#endpoint-https), [`kubernetes`](#endpoint-kubernetes), [`openai_codex_https`](#endpoint-openaicodexhttps), [`postgres`](#endpoint-postgres), [`ssh`](#endpoint-ssh).

### `endpoint "clickhouse_https" "<name>"`

Family: `sql`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of ClickHouse HTTPS hostnames or host:port pairs this endpoint intercepts. |

```hcl
endpoint "clickhouse_https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "clickhouse_native" "<name>"`

Addresses one ClickHouse server reachable
via the binary native protocol. Operators bind a single
clickhouse_credential; the runtime parses the agent's Hello and
substitutes the credential's (user, password) where the agent
embedded a placeholder.

TLS toggles TLS on both hops: the gateway terminates the agent's
TLS using a leaf minted off the gateway CA, parses the Hello in
plaintext, then re-wraps to upstream. The wrapped client therefore
keeps speaking native-over-TLS exactly as it would against the
real cloud ClickHouse — `clawpatrol run` is transparent to its
TLS posture. Default false: WG-only deployments where the operator
wants plaintext on the inner hop (typical self-hosted ClickHouse
on 9000 behind a private network) leave it off.

AcceptInvalidCertificate mirrors clickhouse-client's flag of the
same name: when true and tls is on, the gateway skips upstream cert
validation. Use for self-hosted ClickHouse fronted by a private CA.
Default false keeps full validation against system roots.

Family: `sql`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of ClickHouse native-protocol hostnames or host:port pairs this endpoint intercepts. |
| `port` | `int` | no | The default upstream port for hosts that omit one. Defaults to 9000 without TLS and 9440 with TLS. |
| `tls` | `bool` | no | Enables ClickHouse native-over-TLS on the upstream hop. |
| `accept_invalid_certificate` | `bool` | no | Skips upstream certificate validation when TLS is enabled. |

```hcl
endpoint "clickhouse_native" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "https" "<name>"`

Family: `http`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of HTTPS hostnames or host:port pairs this endpoint intercepts. |

```hcl
endpoint "https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "kubernetes" "<name>"`

ClusterName + Region are EKS auth parameters: when the bound
credential is `aws_credential`, the gateway presigns an STS
GetCallerIdentity URL scoped to (region, cluster_name) and stamps
the result as a `k8s-aws-v1.<…>` bearer. Leave both unset for
self-hosted clusters with a non-EKS credential (bearer_token,
mtls_credential).

Family: `k8s`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | no | An optional list of Kubernetes API hostnames or host:port pairs to intercept. |
| `server` | `string` | no | The Kubernetes API server URL or host:port used when hosts is not set. |
| `ca_cert` | `string` | no | The PEM-encoded cluster CA, often loaded with `<<file:cluster-ca.pem>>`. |
| `description` | `string` | no | Operator-facing text for dashboard display. |
| `cluster_name` | `string` | no | The EKS cluster name used by aws_credential. |
| `region` | `string` | no | The AWS region used by aws_credential for EKS auth. |

```hcl
endpoint "kubernetes" "example" {}
```

### `endpoint "openai_codex_https" "<name>"`

Family: `http`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The chatgpt.com host list intercepted for Codex subscription-auth traffic. |

```hcl
endpoint "openai_codex_https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "postgres" "<name>"`

Addresses a single RDS-or-equivalent server.
Tunnel topologies (kubectl-portforward-ssh and friends) aren't
supported in this iteration — operators run the gateway with
network reachability already arranged.

SSLMode mirrors libpq's sslmode names — "disable" / "prefer" /
"require" / "verify-full". Default "prefer": try TLS, fall back
to plain when the upstream replies 'N'. "require" hard-fails on
'N'. "verify-full" additionally validates the upstream cert
against Host. "disable" skips the SSLRequest probe entirely —
fine for self-hosted pg on a private network where WG already
encrypts the path.

Family: `sql`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | `string` | yes | The upstream Postgres host:port pair. |
| `sslmode` | `string` | no | Controls upstream TLS negotiation. Valid values mirror libpq: "disable", "prefer", "require", and "verify-full". |

```hcl
endpoint "postgres" "example" {
  host = "db.internal:5432"
}
```

### `endpoint "ssh" "<name>"`

Binds one or more host:port tuples. The credentials
that authenticate against it live on credential blocks via the
framework-level `endpoint = X` / `endpoints = [...]` binding. When
a profile wields more than one SSH credential at the endpoint,
each ambiguous credential carries a `user = "..."` disambiguator —
either on its profile-inline entry (`{ credential = X, user = "..." }`)
or on the credential block itself — and the agent's wire-protocol
username picks the matching entry. The agent's username is also
passed through verbatim as the upstream SSH user; credentials
carry only auth material (key / password / host_pubkey), never a
username override.

Family: `ssh`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes | The set of SSH host:port pairs this endpoint intercepts. |

```hcl
endpoint "ssh" "example" {
  hosts = ["api.example.com"]
}
```

## `environment` blocks

Block syntax: `environment "<type>" "<name>" { ... }`

Registered types: [`custom_environment`](#environment-customenvironment).

### `environment "custom_environment" "<name>"`

Is part of the clawpatrol plugin API. It carries
one operator-declared (key, value) pair plus an optional human-
readable description shown by `clawpatrol env --list`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `key` | `string` | yes |  |
| `value` | `string` | yes |  |
| `description` | `string` | no |  |

```hcl
environment "custom_environment" "example" {
  key = "example"
  value = "example"
}
```

## `rule` blocks

Block syntax: `rule "<name>" { ... }`

### `rule "<name>"`

The gohcl-tagged decode target. The match predicate is
family-agnostic at the HCL layer (just a CEL string); the facet's
*cel.Env decides which variables are valid once the family has
been inferred from the endpoint refs.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `endpoint` | `ref(endpoint)` | no | The single endpoint this rule attaches to. Use endpoint or endpoints, not both. |
| `endpoints` | `[]ref(endpoint)` | no | The list of endpoints this rule attaches to. All referenced endpoints must share one protocol family. |
| `priority` | `int` | no | Orders matching rules. Higher values run first; equal priorities preserve declaration order. |
| `disabled` | `bool` | no | Keeps the rule in config while excluding it from runtime evaluation. |
| `condition` | `string` | no | A CEL expression evaluated against the family-specific variable set. An absent / empty condition matches everything — the catch-all pattern (`rule "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `credential` | `ref(credential)` | no | Credential, if set, is a bare-name reference to a credential block. The runtime treats it as an extra match predicate (request must have been dispatched against this credential) evaluated before the CEL expression. |
| `verdict` | `string` | no | The outcome when the rule matches. Set exactly one of `verdict` (`"allow"` / `"deny"`) or `approve`. |
| `reason` | `string` | no | The operator-facing explanation recorded when the rule matches. |
| `approve` | `[]ref(approver)` | no | A list of bare-name approver references. The approvers run in order; the request is allowed only if every stage approves. Set this *or* `verdict`, not both. |

```hcl
rule {}
```

## `tunnel` blocks

Block syntax: `tunnel "<type>" "<name>" { ... }`

Registered types: [`kubernetes_port_forward`](#tunnel-kubernetesportforward), [`local_command`](#tunnel-localcommand), [`ssh_port_forward`](#tunnel-sshportforward), [`tailscale`](#tunnel-tailscale).

### `tunnel "kubernetes_port_forward" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `context` | `string` | no | Selects a kubeconfig context; empty uses the current context. Ignored when Server is set (the plugin builds its own per-tunnel kubeconfig). |
| `namespace` | `string` | no | Selects the Kubernetes namespace for kubectl commands. |
| `pod` | `string` | no | Names an existing pod to port-forward to. Exactly one of pod, service, selector, or template must be set. |
| `service` | `string` | no | Names a service to port-forward to. |
| `selector` | `map[string]string` | no | Matches a ready pod to port-forward to. |
| `template` | `string` | no | A pod manifest to apply and port-forward to. |
| `port` | `int` | yes | The pod-side port the forwarder targets. For service mode it's the *service* port; kubectl resolves the matching targetPort. |
| `cleanup` | `string` | no | Controls whether a template-created pod is deleted on tunnel teardown. "delete" (default) is right for the common create-on-demand case; "keep" disables deletion. |
| `server` | `string` | no | The Kubernetes apiserver URL. When set the plugin writes a per-tunnel kubeconfig (server + ca_cert + bearer minted from the bound credential) and invokes kubectl with --kubeconfig pointing at it; no external kubeconfig or KUBECONFIG env is needed. The Context field is then ignored. |
| `ca_cert` | `string` | no | The cluster CA PEM. Supports `<<file:path.pem>>` for out-of-line storage; the loader inlines the file contents. Required when Server is set against EKS (the apiserver presents a per-cluster CA that no system trust store carries). |
| `cluster_name` | `string` | no | The EKS cluster name, used by an aws_credential to scope the STS presign (sets the X-K8s-Aws-Id header). Only meaningful alongside Server + an aws_credential. |
| `region` | `string` | no | The AWS region the EKS cluster lives in; SigV4 needs it. Only meaningful alongside Server + an aws_credential. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains kubectl access through another tunnel. |
| `credential` | `ref(credential)` | no | References an optional credential block for Kubernetes access. |

```hcl
tunnel "kubernetes_port_forward" "example" {
  port = 30
}
```

### `tunnel "local_command" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | `[]string` | yes | The argv vector to spawn for the tunnel process. |
| `listen` | `string` | yes | The local address the spawned command exposes. |
| `ready_probe` | `string` | no | An optional TCP address to poll before the tunnel is ready. |
| `ready_timeout` | `string` | no | Overrides the default readiness wait duration. |
| `env` | `map[string]string` | no | Adds environment variables to the spawned command. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains this tunnel through another tunnel. |
| `credential` | `ref(credential)` | no | References an optional credential block for the tunnel runtime. |

```hcl
tunnel "local_command" "example" {
  command = ["example"]
  listen = "example"
}
```

### `tunnel "ssh_port_forward" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `bastion` | `string` | no | The SSH server host:port; required when via is unset. |
| `user` | `string` | yes | The SSH username for the bastion login. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains the SSH connection through another tunnel. |
| `credential` | `ref(credential)` | yes | References an ssh credential block used for bastion authentication. |

```hcl
tunnel "ssh_port_forward" "example" {
  bastion = "bastion.example:22"
  user = "example"
  credential = bearer_token.example
}
```

### `tunnel "tailscale" "<name>"`

Configures the tunnel runtime.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `authkey` | `string` | no | The Tailscale auth key; env fallback is CLAWPATROL_TUNNEL_<NAME>_AUTHKEY. |
| `control_url` | `string` | no | Overrides the Tailscale control-plane URL. |
| `hostname` | `string` | no | The tsnet node name; defaults to clawpatrol-tunnel-<name>. |
| `state_dir` | `string` | no | Stores tsnet node state; defaults under the gateway CA directory. |
| `tags` | `[]string` | no | Tailscale tags requested for the tsnet node. |
| `share` | `string` | no | Controls whether runtime instances are singleton, per-endpoint, or per-request. |
| `keepalive` | `string` | no | Keeps an idle tunnel runtime warm for the given duration. |
| `via` | `ref(tunnel)` | no | Chains this tunnel through another tunnel. |
| `credential` | `ref(credential)` | no | References an optional credential block for the tunnel runtime. |

```hcl
tunnel "tailscale" "example" {}
```

