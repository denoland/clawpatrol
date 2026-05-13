# HCL config reference

A clawpatrol gateway config mixes **operational** fields (top-level
plumbing) with **policy** blocks. Operational fields are top-level
attributes; policy blocks (`approver`, `credential`, `tunnel`, `endpoint`, `rule`)
dispatch to a plugin chosen by the block's first label.

## How to read this page

Each block section lists the attributes the loader accepts, with:

- **Type** — the HCL value type. `string`, `bool`, `int` are scalar
  literals; `[]string` is a list of strings; `ref(<kind>)` is a
  bare-name reference to another block of that kind (e.g.
  `credential = github-pat`); `[]ref(<kind>)` is a list of such
  references; nested blocks have their shape described inline.
- **Required** — `yes` if the loader rejects the block when the
  attribute is missing.

Plugin-dispatched kinds (`approver`, `credential`, `tunnel`, `endpoint`, `rule`)
list one subsection per registered type.

## Top-level fields

Every singleton gateway attribute — listen addresses, paths, control-plane joining, WireGuard endpoint, and policy fallbacks — is set directly at the top of `gateway.hcl`. Labeled blocks (`policy`, `profile`, `approver`, `credential`, `endpoint`, `rule`, `tunnel`) are documented in their own sections.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `listen` | `string` | no |  |
| `info_listen` | `string` | no |  |
| `public_url` | `string` | no |  |
| `admin_email` | `string` | no |  |
| `ca_dir` | `string` | no | The legacy path the gateway used to keep the CA cert + ssh host keys on disk. Kept for backwards compat so existing configs still parse and state_dir resolution can fall back to ${ca_dir}/../oauth. New deployments should set state_dir instead — the gateway keeps everything in sqlite. |
| `state_dir` | `string` | no | The directory holding clawpatrol.db. Falls back to OAuthDir (historical name) or ${CADir}/../oauth or ${HOME}/.clawpatrol/state, in that order. |
| `resolver` | `string` | no |  |
| `log_path` | `string` | no |  |
| `oauth_dir` | `string` | no | The historical state directory name. Equivalent to state_dir and kept for backwards compat. |
| `dashboard_secret` | `string` | no |  |
| `insecure_no_dashboard_secret` | `bool` | no | Opts out of dashboard auth. Required (alongside an empty DashboardSecret) for the gateway to serve the dashboard at all — otherwise the secret gate replies with a misconfiguration page on every request. Verbose by design so you can't disable auth by accident. |
| `telemetry` | `bool` | no | Opts in/out of the update-checker / anonymous usage ping (doc/telemetry.md). nil = default on; explicit `telemetry = false` silences the goroutine. Env vars CLAWPATROL_TELEMETRY=0 and DO_NOT_TRACK=1 also work. |
| `session_keep` | `string` | no | The hard retention floor for the sessions table. Sessions whose last_at is older than this get deleted by the background sweeper. Sessions can revive on new activity at any time, so there's no "closed but kept" intermediate state — only last_at matters. Default 720h (30d), "0" / "off" disables. Format accepts time.ParseDuration strings ("30m", "168h", etc.). |
| `authkey` | `string` | no |  |
| `control_url` | `string` | no |  |
| `hostname` | `string` | no |  |
| `control` | `string` | no |  |
| `oauth_client_id` | `string` | no |  |
| `oauth_client_secret` | `string` | no |  |
| `tailscale_tags` | `[]string` | no | The Tailscale device-tag list applied to keys the gateway mints for onboarded clients (`tag:client` etc.). Tailscale-only — ignored in WireGuard mode. |
| `wg_interface` | `string` | no |  |
| `wg_endpoint` | `string` | no |  |
| `wg_server_pub` | `string` | no |  |
| `wg_subnet_cidr` | `string` | no |  |
| `unknown_host` | `string` | no |  |
| `llm_fail_mode` | `string` | no |  |
| `llm_cache_ttl` | `int` | no |  |
| `human_timeout` | `int` | no |  |
| `human_on_timeout` | `string` | no |  |

## `policy "<name>" { ... }`

Defines a named, reusable chunk of policy prose that
`llm_approver` blocks reference by name. The single `text` attribute
is typically a heredoc.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `text` | `string` | yes |  |

```hcl
policy "example" {
  text = <<-EOT
    Example policy text.
  EOT
}
```

## `profile "<name>" { ... }`

Names a set of endpoints. Profiles bind to dashboard owners; an owner's profile determines which endpoints their gateway requests can reach. Rules ride along automatically because they're attached to endpoints.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `endpoints` | `[]ref(endpoint)` | yes | Bare-name endpoint references included in this profile. |

```hcl
profile "default" {
  endpoints = [github, postgres-prod]
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
| `channel` | `string` | yes |  |
| `credential` | `ref(credential)` | no |  |
| `timeout` | `int` | no |  |
| `require_approvers` | `int` | no |  |
| `interactive` | `bool` | no | Toggles in-channel approve/deny buttons. Requires the referenced credential's signing_secret slot pasted via the dashboard AND Slack's Interactivity URL pointed at the gateway. Default false: message includes only an "Open dashboard" link. |

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
| `model` | `string` | yes |  |
| `credential` | `ref(credential)` | yes |  |
| `policy` | `ref(policy)` | no |  |

```hcl
approver "llm_approver" "example" {
  model = "claude-haiku-4-5-20251001"
  credential = example-credential
}
```

## `credential` blocks

Block syntax: `credential "<type>" "<name>" { ... }`

Registered types: [`anthropic_manual_key`](#credential-anthropicmanualkey), [`anthropic_oauth_subscription`](#credential-anthropicoauthsubscription), [`aws_eks_credential`](#credential-awsekscredential), [`bearer_token`](#credential-bearertoken), [`clickhouse_credential`](#credential-clickhousecredential), [`cookie_token`](#credential-cookietoken), [`discord_bot_token`](#credential-discordbottoken), [`gemini_api_key`](#credential-geminiapikey), [`github_oauth`](#credential-githuboauth), [`header_token`](#credential-headertoken), [`mtls_credential`](#credential-mtlscredential), [`notion_oauth`](#credential-notionoauth), [`openai_codex_oauth`](#credential-openaicodexoauth), [`postgres_credential`](#credential-postgrescredential), [`slack_tokens`](#credential-slacktokens), [`ssh`](#credential-ssh), [`tailscale`](#credential-tailscale), [`telegram_bot_token`](#credential-telegrambottoken).

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

### `credential "aws_eks_credential" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `cluster` | `string` | yes |  |
| `region` | `string` | yes |  |
| `profile` | `string` | no |  |

```hcl
credential "aws_eks_credential" "example" {
  cluster = "example"
  region = "example"
}
```

### `credential "bearer_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `idempotency_key` | `bool` | no |  |

```hcl
credential "bearer_token" "example" {}
```

### `credential "clickhouse_credential" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `user` | `string` | no |  |

```hcl
credential "clickhouse_credential" "example" {}
```

### `credential "cookie_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `cookie_name` | `string` | no |  |

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

### `credential "header_token" "<name>"`

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `header` | `string` | yes |  |
| `prefix` | `string` | no |  |

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

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `user` | `string` | no |  |

```hcl
credential "postgres_credential" "example" {}
```

### `credential "slack_tokens" "<name>"`

_No configurable attributes._

```hcl
credential "slack_tokens" "example" {}
```

### `credential "ssh" "<name>"`

_No configurable attributes._

```hcl
credential "ssh" "example" {}
```

### `credential "tailscale" "<name>"`

Has no operator-facing fields — there is
nothing to paste. Per-tailnet selection (control_url, tags) lives
on the tunnel block instead.

_No configurable attributes._

```hcl
credential "tailscale" "example" {}
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
| `hosts` | `[]string` | yes |  |
| `credential` | `ref(credential)` | no |  |

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
| `hosts` | `[]string` | yes |  |
| `port` | `int` | no |  |
| `tls` | `bool` | no |  |
| `accept_invalid_certificate` | `bool` | no |  |
| `credential` | `ref(credential)` | no |  |

```hcl
endpoint "clickhouse_native" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "https" "<name>"`

Family: `http`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes |  |
| `credential` | `ref(credential)` | no |  |
| `credentials` | `[]credential` | no |  |

```hcl
endpoint "https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "kubernetes" "<name>"`

Family: `k8s`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | no |  |
| `server` | `string` | no |  |
| `ca_cert` | `string` | no |  |
| `description` | `string` | no |  |
| `credential` | `ref(credential)` | no |  |

```hcl
endpoint "kubernetes" "example" {}
```

### `endpoint "openai_codex_https" "<name>"`

Family: `http`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes |  |
| `credential` | `ref(credential)` | no |  |
| `credentials` | `[]credential` | no |  |

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
| `host` | `string` | yes |  |
| `database` | `string` | yes |  |
| `sslmode` | `string` | no |  |
| `credential` | `ref(credential)` | no |  |
| `credentials` | `[]credential` | no |  |

```hcl
endpoint "postgres" "example" {
  host = "db.internal:5432"
  database = "appdb"
}
```

### `endpoint "ssh" "<name>"`

Binds one or more host:port tuples to one or more SSH
credentials. The agent's username is the discriminator for
per-username dispatch (mirrors postgres' placeholder-based dispatch,
just spelled `user` because that's what SSH calls it):

	credential = X                                  // any user → X
	credentials = [{ user = "root",   credential = X },
	               { user = "deploy", credential = Y },
	               { credential = Z }]              // fallback

The agent's username is also passed through verbatim as the upstream
SSH user — credentials carry only auth material (key / password /
host_pubkey), never a username override.

Family: `ssh`.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `hosts` | `[]string` | yes |  |
| `credential` | `ref(credential)` | no |  |
| `credentials` | `[]credential` | no |  |

```hcl
endpoint "ssh" "example" {
  hosts = ["api.example.com"]
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
| `endpoint` | `ref(endpoint)` | no |  |
| `endpoints` | `[]ref(endpoint)` | no |  |
| `priority` | `int` | no |  |
| `disabled` | `bool` | no |  |
| `condition` | `string` | no | A CEL expression evaluated against the family-specific variable set. An absent / empty condition matches everything — the catch-all pattern (`rule "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `credential` | `ref(credential)` | no | Credential, if set, is a bare-name reference to a credential block. The runtime treats it as an extra match predicate (request must have been dispatched against this credential) evaluated before the CEL expression. |
| `verdict` | `string` | no | The outcome when the rule matches. Set exactly one of `verdict` (`"allow"` / `"deny"`) or `approve`. |
| `reason` | `string` | no |  |
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
| `context` | `string` | no | Selects a kubeconfig context; empty uses the current context. |
| `namespace` | `string` | no | Selects the Kubernetes namespace for kubectl commands. |
| `pod` | `string` | no | Names an existing pod to port-forward to. Exactly one of pod, service, selector, or template must be set. |
| `service` | `string` | no | Names a service to port-forward to. |
| `selector` | `map[string]string` | no | Matches a ready pod to port-forward to. |
| `template` | `string` | no | A pod manifest to apply and port-forward to. |
| `port` | `int` | yes | The pod-side port the forwarder targets. For service mode it's the *service* port; kubectl resolves the matching targetPort. |
| `cleanup` | `string` | no | Controls whether a template-created pod is deleted on tunnel teardown. "delete" (default) is right for the common create-on-demand case; "keep" disables deletion. |
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
  credential = example-credential
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

