# HCL config reference

> **This page is auto-generated** from the plugin registry under
> `config/plugins/` and the operational structs in `config/`.
> Do not hand-edit. Re-run `go run ./tools/docgen` after changing any
> `hcl:"..."` tag, plugin registration, or struct field comment.

A clawpatrol gateway config mixes **operational** fields (top-level
plumbing) with **policy** blocks. Operational fields decode statically
into `config.Gateway`; policy blocks dispatch to plugins by their
first label.

For prose context (references, namespaces, design rationale) see
[`config/README.md`](https://github.com/denoland/clawpatrol/blob/main/config/README.md);
the page you're reading is the field-by-field reference.

## How to read this page

Each block section lists the attributes the loader accepts, with:

- **Type** — Go type after HCL decode. `string`, `bool`, `int` map to
  the obvious HCL kinds; `[]string` is an HCL list of strings;
  `object` denotes a nested block / object whose shape is
  described inline.
- **Required** — `yes` if the loader rejects the block when the
  attribute is missing.
- **Reference** — when set, the value is a bare-name reference to
  another block of the named kind (e.g. `credential = github-pat`).

Plugin-dispatched kinds (`approver`, `credential`, `endpoint`, `rule`)
list one subsection per registered type.

## Top-level operational fields

Gateway is the fully-loaded clawpatrol gateway config: operational
fields at the top, plus a resolved policy.

Operational fields are still decoded via plain gohcl struct tags —
they're not pluggable. Anything below `tailscale {}` is dispatched
to the plugin registry.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `listen` | `string` | no | — |  |
| `info_listen` | `string` | no | — |  |
| `public_url` | `string` | no | — |  |
| `admin_email` | `string` | no | — |  |
| `ca_dir` | `string` | no | — |  |
| `resolver` | `string` | no | — |  |
| `log_path` | `string` | no | — |  |
| `oauth_dir` | `string` | no | — |  |
| `dashboard_secret` | `string` | no | — |  |
| `insecure_no_dashboard_secret` | `bool` | no | — | InsecureNoDashboardSecret opts out of dashboard auth. Required (alongside an empty DashboardSecret) for the gateway to serve the dashboard at all — otherwise the secret gate replies with a misconfiguration page on every request. Verbose by design so you can't disable auth by accident. |
| `session_keep` | `string` | no | — | SessionKeep is the hard retention floor for the sessions table. Sessions whose last_at is older than this get deleted by the background sweeper. Sessions can revive on new activity at any time, so there's no "closed but kept" intermediate state — only last_at matters. Default 720h (30d), "0" / "off" disables. Format accepts time.ParseDuration strings ("30m", "168h", etc.). |
| `gateway` | `block` | yes | — |  |

### `gateway {}` block

Tailscale mirrors main.go's existing block layout. Kept here so
config.Gateway is self-contained; the operational runtime can read
from this type after Load.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `authkey` | `string` | no | — |  |
| `control_url` | `string` | no | — |  |
| `hostname` | `string` | no | — |  |
| `state_dir` | `string` | no | — |  |
| `control` | `string` | no | — |  |
| `oauth_client_id` | `string` | no | — |  |
| `oauth_client_secret` | `string` | no | — |  |
| `tags` | `[]string` | no | — |  |
| `wg_interface` | `string` | no | — |  |
| `wg_endpoint` | `string` | no | — |  |
| `wg_server_pub` | `string` | no | — |  |
| `wg_subnet_cidr` | `string` | no | — |  |

## `defaults {}`

Defaults captures the singleton defaults {} block.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `unknown_host` | `string` | no | — |  |
| `llm_fail_mode` | `string` | no | — |  |
| `llm_cache_ttl` | `int` | no | — |  |
| `human_timeout` | `int` | no | — |  |
| `human_on_timeout` | `string` | no | — |  |

```hcl
defaults {}
```

## `policy "<name>" { ... }`

PolicyText is the lowered shape of a policy "<name>" {} block:
the heredoc text plus its source range for diagnostic messages.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `text` | `string` | yes | — |  |

```hcl
policy "example" {
  text = <<-EOT
    Example policy text.
  EOT
}
```

## `profile "<name>" { ... }`

Names a set of endpoints. Profiles bind to dashboard owners; an owner's profile determines which endpoints their gateway requests can reach. Rules ride along automatically because they're attached to endpoints.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `endpoints` | `[]string` | yes | endpoint | Bare-name endpoint references included in this profile. |

```hcl
profile "default" {
  endpoints = [github, postgres-prod]
}
```

## `approver` blocks

Block syntax: `approver "<type>" "<name>" { ... }`

Registered types: [`human_approver`](#approver-humanapprover), [`llm_approver`](#approver-llmapprover).

### `approver "human_approver"`

HumanApprover targets one channel. Timeout / require_approvers
override the global defaults block on a per-approver basis.

Credential references a credential whose body satisfies HITLNotifier
(slack_tokens today; future Discord / Telegram / SMTP credentials).
Leave empty for a dashboard-only approver (no channel notification;
operator clicks approve/deny on the dashboard).

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `channel` | `string` | yes | — |  |
| `credential` | `string` | no | credential |  |
| `timeout` | `int` | no | — |  |
| `require_approvers` | `int` | no | — |  |
| `interactive` | `bool` | no | — | Interactive toggles in-channel approve/deny buttons. Requires the referenced credential's signing_secret slot pasted via the dashboard AND Slack's Interactivity URL pointed at the gateway. Default false: message includes only an "Open dashboard" link. |

**References:** `Credential` → credential (optional).

```hcl
approver "human_approver" "example" {
  channel = "#approvals"
}
```

### `approver "llm_approver"`

LLMApprover carries the model + the credential used to authenticate
the call to the model API + the policy text the model judges
against. Inline `policy` is a bare-name reference to a `policy
"<name>" { text = ... }` block — operator declares the prompt once
and reuses across multiple judges.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `model` | `string` | yes | — |  |
| `credential` | `string` | yes | credential |  |
| `policy` | `string` | no | policy |  |

**References:** `Credential` → credential; `Policy` → policy (optional).

```hcl
approver "llm_approver" "example" {
  model = "claude-haiku-4-5-20251001"
  credential = example-credential
}
```

## `credential` blocks

Block syntax: `credential "<type>" "<name>" { ... }`

Registered types: [`anthropic_manual_key`](#credential-anthropicmanualkey), [`anthropic_oauth_subscription`](#credential-anthropicoauthsubscription), [`aws_eks_credential`](#credential-awsekscredential), [`bearer_token`](#credential-bearertoken), [`clickhouse_credential`](#credential-clickhousecredential), [`cookie_token`](#credential-cookietoken), [`gemini_api_key`](#credential-geminiapikey), [`github_oauth`](#credential-githuboauth), [`header_token`](#credential-headertoken), [`mtls_credential`](#credential-mtlscredential), [`notion_oauth`](#credential-notionoauth), [`openai_codex_oauth`](#credential-openaicodexoauth), [`postgres_credential`](#credential-postgrescredential), [`slack_tokens`](#credential-slacktokens), [`ssh`](#credential-ssh), [`telegram_bot_token`](#credential-telegrambottoken).

### `credential "anthropic_manual_key"`

_No configurable attributes._

```hcl
credential "anthropic_manual_key" "example" {}
```

### `credential "anthropic_oauth_subscription"`

_No configurable attributes._

```hcl
credential "anthropic_oauth_subscription" "example" {}
```

### `credential "aws_eks_credential"`

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `cluster` | `string` | yes | — |  |
| `region` | `string` | yes | — |  |
| `profile` | `string` | no | — |  |

```hcl
credential "aws_eks_credential" "example" {
  cluster = "example"
  region = "example"
}
```

### `credential "bearer_token"`

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `idempotency_key` | `bool` | no | — |  |

```hcl
credential "bearer_token" "example" {}
```

### `credential "clickhouse_credential"`

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `user` | `string` | no | — |  |

```hcl
credential "clickhouse_credential" "example" {}
```

### `credential "cookie_token"`

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `cookie_name` | `string` | no | — |  |

```hcl
credential "cookie_token" "example" {}
```

### `credential "gemini_api_key"`

_No configurable attributes._

```hcl
credential "gemini_api_key" "example" {}
```

### `credential "github_oauth"`

_No configurable attributes._

```hcl
credential "github_oauth" "example" {}
```

### `credential "header_token"`

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `header` | `string` | yes | — |  |
| `prefix` | `string` | no | — |  |

```hcl
credential "header_token" "example" {
  header = "X-API-Key"
}
```

### `credential "mtls_credential"`

_No configurable attributes._

```hcl
credential "mtls_credential" "example" {}
```

### `credential "notion_oauth"`

_No configurable attributes._

```hcl
credential "notion_oauth" "example" {}
```

### `credential "openai_codex_oauth"`

_No configurable attributes._

```hcl
credential "openai_codex_oauth" "example" {}
```

### `credential "postgres_credential"`

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `user` | `string` | no | — |  |

```hcl
credential "postgres_credential" "example" {}
```

### `credential "slack_tokens"`

_No configurable attributes._

```hcl
credential "slack_tokens" "example" {}
```

### `credential "ssh"`

_No configurable attributes._

```hcl
credential "ssh" "example" {}
```

### `credential "telegram_bot_token"`

_No configurable attributes._

```hcl
credential "telegram_bot_token" "example" {}
```

## `endpoint` blocks

Block syntax: `endpoint "<type>" "<name>" { ... }`

Registered types: [`clickhouse_https`](#endpoint-clickhousehttps), [`clickhouse_native`](#endpoint-clickhousenative), [`https`](#endpoint-https), [`kubernetes`](#endpoint-kubernetes), [`openai_codex_https`](#endpoint-openaicodexhttps), [`postgres`](#endpoint-postgres), [`ssh`](#endpoint-ssh).

### `endpoint "clickhouse_https"`

Family: `sql`.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `hosts` | `[]string` | yes | — |  |
| `credential` | `string` | no | credential |  |

**References:** `Credential` → credential (optional).

```hcl
endpoint "clickhouse_https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "clickhouse_native"`

ClickhouseNativeEndpoint addresses one ClickHouse server reachable
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

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `hosts` | `[]string` | yes | — |  |
| `port` | `int` | no | — |  |
| `tls` | `bool` | no | — |  |
| `accept_invalid_certificate` | `bool` | no | — |  |
| `credential` | `string` | no | credential |  |

**References:** `Credential` → credential (optional).

```hcl
endpoint "clickhouse_native" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "https"`

Family: `https`.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `hosts` | `[]string` | yes | — |  |
| `credential` | `string` | no | credential |  |
| `credentials` | `object` | no | — |  |

**References:** `Credential` → credential (optional).

```hcl
endpoint "https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "kubernetes"`

Family: `k8s`.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `hosts` | `[]string` | no | — |  |
| `server` | `string` | no | — |  |
| `ca_cert` | `string` | no | — |  |
| `description` | `string` | no | — |  |
| `credential` | `string` | no | credential |  |

**References:** `Credential` → credential (optional).

```hcl
endpoint "kubernetes" "example" {}
```

### `endpoint "openai_codex_https"`

Family: `https`.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `hosts` | `[]string` | yes | — |  |
| `credential` | `string` | no | credential |  |
| `credentials` | `object` | no | — |  |

**References:** `Credential` → credential (optional).

```hcl
endpoint "openai_codex_https" "example" {
  hosts = ["api.example.com"]
}
```

### `endpoint "postgres"`

PostgresEndpoint addresses a single RDS-or-equivalent server.
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

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `host` | `string` | yes | — |  |
| `database` | `string` | yes | — |  |
| `sslmode` | `string` | no | — |  |
| `credential` | `string` | no | credential |  |
| `credentials` | `object` | no | — |  |

**References:** `Credential` → credential (optional).

```hcl
endpoint "postgres" "example" {
  host = "db.internal:5432"
  database = "appdb"
}
```

### `endpoint "ssh"`

SSHEndpoint binds one or more host:port tuples to one or more SSH
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

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `hosts` | `[]string` | yes | — |  |
| `credential` | `string` | no | credential |  |
| `credentials` | `object` | no | — |  |

**References:** `Credential` → credential (optional).

```hcl
endpoint "ssh" "example" {
  hosts = ["api.example.com"]
}
```

## `rule` blocks

Block syntax: `rule "<type>" "<name>" { ... }`

Registered types: [`http_rule`](#rule-httprule), [`k8s_rule`](#rule-k8srule), [`sql_rule`](#rule-sqlrule).

### `rule "http_rule"`

RuleBody is the shared shape across all three rule types. The
match keys vary by family (interpreted in Build), but the outer
frame is identical: endpoint targeting, priority, outcome.

Targets endpoints of family: `https`.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `endpoint` | `string` | no | endpoint |  |
| `endpoints` | `[]string` | no | endpoint |  |
| `priority` | `int` | no | — |  |
| `disabled` | `bool` | no | — |  |
| `match` | `object` | no | — | Match is decoded raw and interpreted per family in Build. An absent match block matches everything — the v14 catch-all pattern (`rule "..." "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `verdict` | `string` | no | — | Outcome: exactly one of verdict / approve. |
| `reason` | `string` | no | — |  |
| `approve` | `object` | no | — |  |

**References:** `Endpoint` → endpoint (optional); `Endpoints[*]` → endpoint (optional).

**`match` keys** (single string or list of strings each):

- family `https`: `method`, `path`, `query`, `headers`, `body_json`, `body_contains`, `credential`

```hcl
rule "http_rule" "example" {}
```

### `rule "k8s_rule"`

RuleBody is the shared shape across all three rule types. The
match keys vary by family (interpreted in Build), but the outer
frame is identical: endpoint targeting, priority, outcome.

Targets endpoints of family: `k8s`.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `endpoint` | `string` | no | endpoint |  |
| `endpoints` | `[]string` | no | endpoint |  |
| `priority` | `int` | no | — |  |
| `disabled` | `bool` | no | — |  |
| `match` | `object` | no | — | Match is decoded raw and interpreted per family in Build. An absent match block matches everything — the v14 catch-all pattern (`rule "..." "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `verdict` | `string` | no | — | Outcome: exactly one of verdict / approve. |
| `reason` | `string` | no | — |  |
| `approve` | `object` | no | — |  |

**References:** `Endpoint` → endpoint (optional); `Endpoints[*]` → endpoint (optional).

**`match` keys** (single string or list of strings each):

- family `k8s`: `resource`, `verb`, `namespace`, `name`, `params`, `credential`

```hcl
rule "k8s_rule" "example" {}
```

### `rule "sql_rule"`

RuleBody is the shared shape across all three rule types. The
match keys vary by family (interpreted in Build), but the outer
frame is identical: endpoint targeting, priority, outcome.

Targets endpoints of family: `sql`.

| Attribute | Type | Required | Reference | Description |
|-----------|------|----------|-----------|-------------|
| `endpoint` | `string` | no | endpoint |  |
| `endpoints` | `[]string` | no | endpoint |  |
| `priority` | `int` | no | — |  |
| `disabled` | `bool` | no | — |  |
| `match` | `object` | no | — | Match is decoded raw and interpreted per family in Build. An absent match block matches everything — the v14 catch-all pattern (`rule "..." "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `verdict` | `string` | no | — | Outcome: exactly one of verdict / approve. |
| `reason` | `string` | no | — |  |
| `approve` | `object` | no | — |  |

**References:** `Endpoint` → endpoint (optional); `Endpoints[*]` → endpoint (optional).

**`match` keys** (single string or list of strings each):

- family `sql`: `verb`, `tables`, `function`, `statement`, `statement_regex`, `credential`

```hcl
rule "sql_rule" "example" {}
```

