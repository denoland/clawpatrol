# Configuration reference

Auto-generated from the source of truth in `config/plugins/`.
Do not hand-edit; run `go run ./tools/docgen -out site/doc/15-config-reference.md` to regenerate.

A clawpatrol gateway loads one HCL file (typically `/etc/clawpatrol/gateway.hcl`).
The file mixes **operational** fields (gateway plumbing) with **policy** blocks. Operational
fields decode statically; policy blocks dispatch to plugins by their first label. References
between named entities are bare names — no kind prefix, no type prefix — and the namespace
is flat.

For a worked tour of the grammar, see `config/README.md`; this page is the
exhaustive field reference.

## Top-level fields

Gateway is the fully-loaded clawpatrol gateway config: operational fields at the top, plus a resolved policy.

Operational fields are still decoded via plain gohcl struct tags — they're not pluggable. Anything below `tailscale {}` is dispatched to the plugin registry.

| Field | Type | Required | Description |
|---|---|---|---|
| `listen` | string | no |  |
| `info_listen` | string | no |  |
| `public_url` | string | no |  |
| `admin_email` | string | no |  |
| `ca_dir` | string | no |  |
| `resolver` | string | no |  |
| `log_path` | string | no |  |
| `oauth_dir` | string | no |  |
| `dashboard_secret` | string | no |  |
| `insecure_no_dashboard_secret` | bool | no | InsecureNoDashboardSecret opts out of dashboard auth. Required (alongside an empty DashboardSecret) for the gateway to serve the dashboard at all — otherwise the secret gate replies with a misconfiguration page on every request. Verbose by design so you can't disable auth by accident. |
| `session_keep` | string | no | SessionKeep is the hard retention floor for the sessions table. Sessions whose last_at is older than this get deleted by the background sweeper. Sessions can revive on new activity at any time, so there's no "closed but kept" intermediate state — only last_at matters. Default 720h (30d), "0" / "off" disables. Format accepts time.ParseDuration strings ("30m", "168h", etc.). |

### `gateway {}` block

| Field | Type | Required | Description |
|---|---|---|---|
| `authkey` | string | no |  |
| `control_url` | string | no |  |
| `hostname` | string | no |  |
| `state_dir` | string | no |  |
| `control` | string | no |  |
| `oauth_client_id` | string | no |  |
| `oauth_client_secret` | string | no |  |
| `tags` | list of string | no |  |
| `wg_interface` | string | no |  |
| `wg_endpoint` | string | no |  |
| `wg_server_pub` | string | no |  |
| `wg_subnet_cidr` | string | no |  |

## `defaults {}`

Defaults captures the singleton defaults {} block.

| Field | Type | Required | Description |
|---|---|---|---|
| `unknown_host` | string | no |  |
| `llm_fail_mode` | string | no |  |
| `llm_cache_ttl` | number | no |  |
| `human_timeout` | number | no |  |
| `human_on_timeout` | string | no |  |

Example:

```hcl
defaults {
  unknown_host       = "<value>"
  llm_fail_mode      = "<value>"
  llm_cache_ttl      = 0
  human_timeout      = 0
  human_on_timeout   = "<value>"
}
```

## `policy "<name>" {}`

Reusable LLM proctor prompt. Referenced by name from `approver` blocks (LLM judges) and `rule` `approve` chains. Heredoc-friendly.

| Field | Type | Required | Description |
|---|---|---|---|
| `text` | string | yes |  |

Example:

```hcl
policy "k8s-exec-content" {
  text = <<-EOT
    Inspect the kubectl exec command (each ?command= argv element).
    Deny if it dumps env vars, reads sensitive host-mount files...
  EOT
}
```

## `profile "<name>" {}`

Endpoint membership list. A device's profile gets exactly the endpoints its profile names; rules ride along automatically because they're attached to endpoints.

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoints` | list of string | yes | Bare-name references to declared endpoints. |

Example:

```hcl
profile "kaju" {
  endpoints = [github-kaju, slack-kaju, grafana]
}
```

## `device "<ip>" {}`

Per-device rule overrides. Nested `rule "<type>" "<name>"` blocks decode through the same plugin pipeline as top-level rules; the compiler pins each rule to the device IP automatically and adds a +1000 priority bump so device overrides win against profile rules at the same explicit priority.

- Nested rules reference the device's IP implicitly. Do **not** add `peer_ip = ...` — the dispatcher handles peer scoping.
- An endpoint referenced by a device rule is auto-added to every profile's HostIndex so dispatch finds it. Other devices' traffic to those hosts gets MITM'd but no rule fires.
- The dashboard's per-device editor accepts `device {}` blocks alongside `endpoint`, `credential`, `approver`, and `policy` blocks.

Example:

```hcl
device "10.55.0.2" {
  rule "http_rule" "deny-tinyclouds" {
    endpoint = github-api
    match    = { path = "/tinyclouds/*" }
    verdict  = "deny"
    reason   = "this device shouldn't reach tinyclouds"
  }
}
```

## Approvers

Who arbitrates `approve = [...]` chains. Reference an approver by its bare name from a rule's `approve` list. The built-in `dashboard` approver does not require a block — `approve = [dashboard]` resolves to the built-in.

### `approver "human_approver" "<name>"`

HumanApprover targets one channel. Timeout / require_approvers override the global defaults block on a per-approver basis.

Credential references a credential whose body satisfies HITLNotifier (slack_tokens today; future Discord / Telegram / SMTP credentials). Leave empty for a dashboard-only approver (no channel notification; operator clicks approve/deny on the dashboard).

| Field | Type | Required | Description |
|---|---|---|---|
| `channel` | string | yes |  |
| `credential` | string | no |  |
| `timeout` | number | no |  |
| `require_approvers` | number | no |  |
| `interactive` | bool | no | Interactive toggles in-channel approve/deny buttons. Requires the referenced credential's signing_secret slot pasted via the dashboard AND Slack's Interactivity URL pointed at the gateway. Default false: message includes only an "Open dashboard" link. |

Example:

```hcl
approver "human_approver" "<name>" {
  channel      = "<value>"
}
```

### `approver "llm_approver" "<name>"`

LLMApprover carries the model + the credential used to authenticate the call to the model API + the policy text the model judges against. Inline `policy` is a bare-name reference to a `policy "<name>" { text = ... }` block — operator declares the prompt once and reuses across multiple judges.

| Field | Type | Required | Description |
|---|---|---|---|
| `model` | string | yes |  |
| `credential` | string | yes |  |
| `policy` | string | no |  |

Example:

```hcl
approver "llm_approver" "<name>" {
  model        = "<value>"
  credential   = "<value>"
}
```

## Credentials

Typed handle to a secret. The actual secret bytes live in the gateway's secret store (env vars by default, keyed by `CLAWPATROL_SECRET_<UPPER_NAME>`); the credential block carries only how-to-inject parameters.

### `credential "anthropic_manual_key" "<name>"`

anthropic_manual_key: Anthropic API key stamped into the `x-api-key` header (Anthropic's bearer-style header for direct API keys; OAuth subscriptions use Authorization, see anthropic_oauth.go).

_No body attributes._

Example:

```hcl
credential "anthropic_manual_key" "<name>" {}
```

### `credential "anthropic_oauth_subscription" "<name>"`

anthropic_oauth_subscription: claude.ai → console.anthropic.com OAuth flow. Stamps the bearer + the beta header that gates Anthropic's OAuth-backed access.

_No body attributes._

Example:

```hcl
credential "anthropic_oauth_subscription" "<name>" {}
```

### `credential "aws_eks_credential" "<name>"`

aws_eks_credential: the kubernetes endpoint plugin runs `aws eks get-token` at request time using these parameters and uses the resulting bearer as the Authorization header. Configured via mTLS / IAM at the cluster level — no paste-secret slots, no env pushdown.

| Field | Type | Required | Description |
|---|---|---|---|
| `cluster` | string | yes |  |
| `region` | string | yes |  |
| `profile` | string | no |  |

Example:

```hcl
credential "aws_eks_credential" "<name>" {
  cluster      = "<value>"
  region       = "<value>"
}
```

### `credential "bearer_token" "<name>"`

bearer_token: Authorization: Bearer <secret>. Optional idempotency_key flag stamps a derived Idempotency-Key header on writes when the agent didn't already.

| Field | Type | Required | Description |
|---|---|---|---|
| `idempotency_key` | bool | no |  |

Example:

```hcl
credential "bearer_token" "<name>" {}
```

### `credential "clickhouse_credential" "<name>"`

clickhouse_credential: HTTPS API takes user + password as query params (?user=…&password=…) or basic-auth header. We populate both — basic-auth handles default-auth ClickHouse setups, query params handle setups that disable header auth.

| Field | Type | Required | Description |
|---|---|---|---|
| `user` | string | no |  |

Example:

```hcl
credential "clickhouse_credential" "<name>" {}
```

### `credential "cookie_token" "<name>"`

cookie_token: stamp the secret as an HTTP cookie under the configured name.

| Field | Type | Required | Description |
|---|---|---|---|
| `cookie_name` | string | no |  |

Example:

```hcl
credential "cookie_token" "<name>" {}
```

### `credential "gemini_api_key" "<name>"`

gemini_api_key: Google Gemini accepts the API key in either the `x-goog-api-key` header or the `?key=` query parameter. Always overwrite both — agents that send placeholder values get them swapped; agents that don't send anything get the real key stamped in.

_No body attributes._

Example:

```hcl
credential "gemini_api_key" "<name>" {}
```

### `credential "github_oauth" "<name>"`

github_oauth: bearer token from gh's device-flow OAuth. Used by gh CLI + the GitHub REST API (api.github.com / raw.githubusercontent.com).

_No body attributes._

Example:

```hcl
credential "github_oauth" "<name>" {}
```

### `credential "header_token" "<name>"`

header_token: stamp the secret onto an arbitrary header, optionally prefixed (e.g. "Bearer ", "Token ").

| Field | Type | Required | Description |
|---|---|---|---|
| `header` | string | yes |  |
| `prefix` | string | no |  |

Example:

```hcl
credential "header_token" "<name>" {
  header       = "<value>"
}
```

### `credential "mtls_credential" "<name>"`

mtls_credential: client cert + key (+ optional CA bundle) for mTLS-authenticated upstreams (k8s API servers, internal CAs). Configures the upstream tls.Config rather than stamping a header.

_No body attributes._

Example:

```hcl
credential "mtls_credential" "<name>" {}
```

### `credential "notion_oauth" "<name>"`

notion_oauth: Bearer token in Authorization + Notion-Version header (Notion's API requires the version, defaults to a recent stable).

_No body attributes._

Example:

```hcl
credential "notion_oauth" "<name>" {}
```

### `credential "openai_codex_oauth" "<name>"`

openai_codex_oauth: bearer token for the codex CLI's OAuth flow. api.openai.com + chatgpt.com both accept Authorization: Bearer.

_No body attributes._

Example:

```hcl
credential "openai_codex_oauth" "<name>" {}
```

### `credential "postgres_credential" "<name>"`

postgres_credential: the wire-protocol user the runtime uses when terminating upstream auth on the agent's behalf. User is the HCL field; password lives in the secret store under the credential's bare name (operator pastes via the dashboard's Postgres slot).

| Field | Type | Required | Description |
|---|---|---|---|
| `user` | string | no |  |

Example:

```hcl
credential "postgres_credential" "<name>" {}
```

### `credential "slack_tokens" "<name>"`

slack_tokens: bot + app token pair plus the optional signing secret. Implements:

  - HTTPCredentialRuntime — pick the right token per Slack endpoint
    and stamp Authorization: Bearer.
  - HITLNotifier          — post Block Kit approval prompts to a
    channel; powers the human_approver plugin without approvers
    having to know anything Slack-specific.
  - WebhookProvider       — handle Slack's interactive (button-click)
    callback. Mounted by main at /api/cred/<credName>/interactive.

Adding another notification channel (Discord, Telegram, SMTP) is a new credential plugin with its own NotifyHITL — no human_approver / runtime.go changes.

_No body attributes._

Example:

```hcl
credential "slack_tokens" "<name>" {}
```

### `credential "ssh" "<name>"`

ssh credential: the auth material the SSH endpoint runtime replays upstream on the agent's behalf. The credential carries only key / password / host-pubkey-pin — the username sent upstream is the one the agent typed, passed through verbatim. Per-username dispatch (e.g. `ssh root@host` vs `ssh deploy@host` picking different keys) lives on the endpoint via the `credentials = [{user=..., credential=...}]` list, mirroring postgres' placeholder-based dispatch.

Material is split across slots so operators can paste a multi-line PEM into one textarea and a single-line passphrase into another:

  private_key  multi-line   OpenSSH / PKCS#8 / PKCS#1 PEM
  passphrase   single-line  optional, decrypts private_key
  password     single-line  optional, used when no key is set
  host_pubkey  single-line  optional, ssh-keyscan-style line for
                            upstream host pinning

At least one of (private_key, password) must be filled at runtime — the endpoint surfaces a clear error to the agent if both are empty.

_No body attributes._

Example:

```hcl
credential "ssh" "<name>" {}
```

### `credential "telegram_bot_token" "<name>"`

telegram_bot_token: bot token lives in the URL path (/bot<TOKEN>/<METHOD>) and sometimes in the request body (setWebhook posts a URL containing the token). We swap every occurrence of the operator-emitted placeholder with the real secret — operator's CLI uses the placeholder verbatim; gateway substitutes globally so the token never hits the upstream as the placeholder and never leaks to logs.

Telegram doesn't appear in `clawpatrol env` because Telegram SDKs take the token as an explicit argument rather than reading it from the env, so there's nothing to "push down".

_No body attributes._

Example:

```hcl
credential "telegram_bot_token" "<name>" {}
```

## Endpoints

Typed upstream binding. Each endpoint type maps to a protocol family (`https`, `sql`, `k8s`, `ssh`); rules constrain themselves to a matching family.

### `endpoint "clickhouse_https" "<name>"`

**Family:** `sql`.

clickhouse_https endpoint: HTTPS API surface for ClickHouse. Pairs with clickhouse_native (same upstream cluster, different protocol) so rules can target both via `endpoints = [ch-https, ch-native]`.

| Field | Type | Required | Description |
|---|---|---|---|
| `hosts` | list of string | yes |  |
| `credential` | string | no |  |

Example:

```hcl
endpoint "clickhouse_https" "<name>" {
  hosts        = ["<value>"]
}
```

### `endpoint "clickhouse_native" "<name>"`

**Family:** `sql`.

ClickhouseNativeEndpoint addresses one ClickHouse server reachable via the binary native protocol. Operators bind a single clickhouse_credential; the runtime parses the agent's Hello and substitutes the credential's (user, password) where the agent embedded a placeholder.

TLS toggles TLS on both hops: the gateway terminates the agent's TLS using a leaf minted off the gateway CA, parses the Hello in plaintext, then re-wraps to upstream. The wrapped client therefore keeps speaking native-over-TLS exactly as it would against the real cloud ClickHouse — `clawpatrol run` is transparent to its TLS posture. Default false: WG-only deployments where the operator wants plaintext on the inner hop (typical self-hosted ClickHouse on 9000 behind a private network) leave it off.

AcceptInvalidCertificate mirrors clickhouse-client's flag of the same name: when true and tls is on, the gateway skips upstream cert validation. Use for self-hosted ClickHouse fronted by a private CA. Default false keeps full validation against system roots.

| Field | Type | Required | Description |
|---|---|---|---|
| `hosts` | list of string | yes |  |
| `port` | number | no |  |
| `tls` | bool | no |  |
| `accept_invalid_certificate` | bool | no |  |
| `credential` | string | no |  |

Example:

```hcl
endpoint "clickhouse_native" "<name>" {
  hosts        = ["<value>"]
}
```

### `endpoint "https" "<name>"`

**Family:** `https`.

https endpoint: anything that speaks TLS-wrapped HTTP. Covers most API-style upstreams. The kubernetes endpoint is HTTPS underneath too but ships as its own type because it carries server / ca_cert metadata HTTPS doesn't.

| Field | Type | Required | Description |
|---|---|---|---|
| `hosts` | list of string | yes |  |
| `credential` | string | no |  |
| `credentials` | list of object | no |  |

Example:

```hcl
endpoint "https" "<name>" {
  hosts        = ["<value>"]
}
```

### `endpoint "kubernetes" "<name>"`

**Family:** `k8s`.

kubernetes endpoint: self-hosted clusters (server + ca_cert) and managed clusters (hosts + EKS-style credential resolved at request time).

| Field | Type | Required | Description |
|---|---|---|---|
| `hosts` | list of string | no |  |
| `server` | string | no |  |
| `ca_cert` | string | no |  |
| `description` | string | no |  |
| `credential` | string | no |  |

Example:

```hcl
endpoint "kubernetes" "<name>" {}
```

### `endpoint "openai_codex_https" "<name>"`

**Family:** `https`.

openai_codex_https endpoint: chatgpt.com path for codex-cli's subscription auth flow. Pushes a synthesized Agent Identity JWT down via env (CODEX_ACCESS_TOKEN / CODEX_AGENT_IDENTITY) so codex enters AgentIdentity mode and routes to chatgpt.com on its own. At MITM time we serve the matching JWKS at `/backend-api/wham/agent-identities/jwks` and stub the agent-task registration POST. Codex's Authorization gets overwritten by the bound credential plugin (openai_codex_oauth) before forwarding upstream, so the AgentAssertion never has to validate against OpenAI's real identity service.

Sample HCL:

	credential "openai_codex_oauth" "codex" {}

	endpoint "openai_codex_https" "codex" {
	  hosts      = ["chatgpt.com"]
	  credential = codex
	}

| Field | Type | Required | Description |
|---|---|---|---|
| `hosts` | list of string | yes |  |
| `credential` | string | no |  |
| `credentials` | list of object | no |  |

Example:

```hcl
endpoint "openai_codex_https" "<name>" {
  hosts        = ["<value>"]
}
```

### `endpoint "postgres" "<name>"`

**Family:** `sql`.

PostgresEndpoint addresses a single RDS-or-equivalent server. Tunnel topologies (kubectl-portforward-ssh and friends) aren't supported in this iteration — operators run the gateway with network reachability already arranged.

SSLMode mirrors libpq's sslmode names — "disable" / "prefer" / "require" / "verify-full". Default "prefer": try TLS, fall back to plain when the upstream replies 'N'. "require" hard-fails on 'N'. "verify-full" additionally validates the upstream cert against Host. "disable" skips the SSLRequest probe entirely — fine for self-hosted pg on a private network where WG already encrypts the path.

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | yes |  |
| `database` | string | yes |  |
| `sslmode` | string | no |  |
| `credential` | string | no |  |
| `credentials` | list of object | no |  |

Example:

```hcl
endpoint "postgres" "<name>" {
  host         = "<value>"
  database     = "<value>"
}
```

### `endpoint "ssh" "<name>"`

**Family:** `ssh`.

SSHEndpoint binds one or more host:port tuples to one or more SSH credentials. The agent's username is the discriminator for per-username dispatch (mirrors postgres' placeholder-based dispatch, just spelled `user` because that's what SSH calls it):

	credential = X                                  // any user → X
	credentials = [{ user = "root",   credential = X },
	               { user = "deploy", credential = Y },
	               { credential = Z }]              // fallback

The agent's username is also passed through verbatim as the upstream SSH user — credentials carry only auth material (key / password / host_pubkey), never a username override.

| Field | Type | Required | Description |
|---|---|---|---|
| `hosts` | list of string | yes |  |
| `credential` | string | no |  |
| `credentials` | list of object | no |  |

Example:

```hcl
endpoint "ssh" "<name>" {
  hosts        = ["<value>"]
}
```

## Rules

One policy decision targeting one or more endpoints. Each rule type is constrained to a matching endpoint family. The shared `RuleBody` schema below applies to all rule types; the per-family match keys are listed under each type.

### `rule "http_rule" "<name>"`

**Endpoint families:** `https`.

RuleBody is the shared shape across all three rule types. The match keys vary by family (interpreted in Build), but the outer frame is identical: endpoint targeting, priority, outcome.

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoint` | string | no |  |
| `endpoints` | list of string | no |  |
| `priority` | number | no |  |
| `disabled` | bool | no |  |
| `match` | object | no | Match is decoded raw and interpreted per family in Build. An absent match block matches everything — the v14 catch-all pattern (`rule "..." "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `verdict` | string | no | Outcome: exactly one of verdict / approve. |
| `reason` | string | no |  |
| `approve` | list | no |  |

**`match` keys (http_rule):** `body_contains`, `body_json`, `credential`, `headers`, `method`, `path`, `query`. Each value accepts a single string or a list (any-of). Strings starting with `!` are negated.

Example:

```hcl
rule "http_rule" "<name>" {}
```

### `rule "k8s_rule" "<name>"`

**Endpoint families:** `k8s`.

RuleBody is the shared shape across all three rule types. The match keys vary by family (interpreted in Build), but the outer frame is identical: endpoint targeting, priority, outcome.

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoint` | string | no |  |
| `endpoints` | list of string | no |  |
| `priority` | number | no |  |
| `disabled` | bool | no |  |
| `match` | object | no | Match is decoded raw and interpreted per family in Build. An absent match block matches everything — the v14 catch-all pattern (`rule "..." "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `verdict` | string | no | Outcome: exactly one of verdict / approve. |
| `reason` | string | no |  |
| `approve` | list | no |  |

**`match` keys (k8s_rule):** `credential`, `name`, `namespace`, `params`, `resource`, `verb`. Each value accepts a single string or a list (any-of). Strings starting with `!` are negated.

Example:

```hcl
rule "k8s_rule" "<name>" {}
```

### `rule "sql_rule" "<name>"`

**Endpoint families:** `sql`.

RuleBody is the shared shape across all three rule types. The match keys vary by family (interpreted in Build), but the outer frame is identical: endpoint targeting, priority, outcome.

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoint` | string | no |  |
| `endpoints` | list of string | no |  |
| `priority` | number | no |  |
| `disabled` | bool | no |  |
| `match` | object | no | Match is decoded raw and interpreted per family in Build. An absent match block matches everything — the v14 catch-all pattern (`rule "..." "X-default" { priority = -100; verdict = "deny" }`) relies on this. |
| `verdict` | string | no | Outcome: exactly one of verdict / approve. |
| `reason` | string | no |  |
| `approve` | list | no |  |

**`match` keys (sql_rule):** `credential`, `function`, `statement`, `statement_regex`, `tables`, `verb`. Each value accepts a single string or a list (any-of). Strings starting with `!` are negated.

Example:

```hcl
rule "sql_rule" "<name>" {}
```
