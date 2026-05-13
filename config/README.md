# clawpatrol policy grammar

`config/` is clawpatrol's HCL policy loader. The grammar is a typed-
block dialect — every named entity declares its kind + type via two
labels, and operators reference entities by bare name. This README
is the canonical syntax reference; the runtime semantics live in
`config/runtime/` and the per-plugin schemas in `config/plugins/`.

A complete example fixture lives at [`testdata/full.hcl`](testdata/full.hcl).

## Top-level structure

A policy file mixes **operational** fields (gateway plumbing) with
**policy** blocks. Operational fields decode statically; policy
blocks dispatch to plugins by their first label.

```hcl
# Top-level singletons — read by the gateway daemon at boot.
# Listen / paths / public URL:
listen      = "0.0.0.0:8443"
log_path    = "/opt/clawpatrol/gateway.log"
state_dir   = "/opt/clawpatrol/state"
public_url  = "http://gateway.internal:8080"
admin_email = "ops@example.com"

# Control-plane joining:
control     = "wireguard"
wg_endpoint = "203.0.113.10:51820"

# Policy fallbacks:
unknown_host  = "passthrough"
llm_fail_mode = "closed"

# Labeled policy blocks — dispatched to plugins.
approver "<type>" "<name>" { ... }
policy   "<name>" { ... }
credential "<type>" "<name>" { ... }
endpoint "<type>" "<name>" { ... }
rule "<type>" "<name>" { ... }
profile "<name>" { ... }
device "<ip>" { rule ... ... { ... } }
```

## Names + references

Every named entity (approver, policy, credential, endpoint, rule,
profile) shares **one flat namespace**. Names are globally unique;
collisions are a load error.

References are **bare names** — no kind prefix, no type prefix:

```hcl
endpoint    = pg-deployng        # not  postgres.pg-deployng
credentials = [github-pat]       # not  credential.bearer_token...
approve     = [content-safety]   # not  approver.llm_approver.fast
```

The two-label declaration carries type information for schema
validation; reference syntax doesn't repeat it. Cross-kind kind
mismatches (`endpoint = some-credential`) surface at load time with
diagnostics that point at both the misuse site and the canonical
declaration.

## Kinds

### Policy defaults (top-level)

Global fallbacks for fail-mode, cache TTL, unknown-host policy.

```hcl
unknown_host     = "passthrough"   # "passthrough" | "deny"
llm_fail_mode    = "closed"        # "closed" | "open"
llm_cache_ttl    = 300             # seconds
human_timeout    = 600             # seconds
human_on_timeout = "deny"          # "deny" | "allow"
```

### `approver "<type>" "<name>" { ... }`

Who arbitrates `approve = [...]` chains. Built-in types:

- `llm_approver` — Claude / GPT proctor. `model = "..."`.
- `human_approver` — Slack channel + optional N-of-N quorum.
  `channel = "#..."`, `timeout = <seconds>`,
  `require_approvers = <int>`.

```hcl
approver "llm_approver" "fast" { model = "claude-haiku-4-5-20251001" }
approver "human_approver" "billing-strict" {
  channel           = "#billing-approvals"
  require_approvers = 2
}
```

### `policy "<name>" { text = "..." }`

Reusable LLM proctor prompt. Referenced from approve-chain stages.
Heredoc-friendly:

```hcl
policy "k8s-exec-content" {
  text = <<-EOT
    Inspect the kubectl exec command (each ?command= argv element).
    Deny if it dumps env vars, reads sensitive host-mount files...
  EOT
}
```

### `credential "<type>" "<name>" { ... }`

Typed handle to a secret. The actual secret bytes live in the
gateway's secret store (env vars by default, keyed by
`CLAWPATROL_SECRET_<UPPER_NAME>`); the credential block carries only
how-to-inject parameters.

| Type | Inject shape |
|------|-------------|
| `bearer_token` | `Authorization: Bearer <secret>` |
| `cookie_token` | `Cookie: <cookie_name>=<secret>` |
| `header_token` | `<header>: <prefix><secret>` |
| `mtls_credential` | client cert in upstream TLS handshake |
| `postgres_credential` | postgres StartupMessage password swap |
| `anthropic_manual_key` | `x-api-key: <secret>` |
| `anthropic_oauth_subscription` | OAuth bearer + Anthropic beta gate |
| `slack_tokens` / `telegram_bot_token` / `gemini_api_key` /<br>`openai_codex_oauth` / `notion_oauth` / `clickhouse_credential` /<br>`aws_eks_credential` | schema-only today (runtime stubs land in follow-ups) |

mTLS env var convention:
`CLAWPATROL_SECRET_<NAME>_CERT`,
`CLAWPATROL_SECRET_<NAME>_KEY`,
`CLAWPATROL_SECRET_<NAME>_CA`. Values starting with `@` are read
off disk (`@/etc/k8s/cert.pem`).

### `endpoint "<type>" "<name>" { ... }`

Typed upstream binding. Built-in types map to protocol families:

| Type | Family | Runtime status |
|------|--------|----------------|
| `https` | `https` | wired |
| `kubernetes` | `k8s` | wired (HTTPS underneath; mTLS supported) |
| `postgres` | `sql` | wired (SSL refused; SQL matchers + approve chains) |
| `clickhouse_https` | `sql` | schema-only |
| `clickhouse_native` | `sql` | schema-only |

Credential binding has two shapes:

```hcl
# Singular — agent sends nothing special; gateway always injects.
endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = github-pat
}

# Multi-credential dispatch via placeholder. Agent embeds the
# placeholder string in the auth slot; gateway swaps it for the
# matching real secret. The trailing no-placeholder entry is the
# fallback when no agent-side placeholder matched.
endpoint "https" "orb" {
  hosts = ["api.withorb.com"]
  credentials = [
    { placeholder = "PH_orb_test", credential = orb-test-key },
    { placeholder = "PH_orb_prod", credential = orb-prod-key },
  ]
}
```

Family-specific extras: postgres has `host` (with port) + `database`;
kubernetes has `server` / `ca_cert` / `description` (file-include
markers like `<<file:k8s-ca.pem>>` resolve at load relative to the
config file's directory).

### `rule "<type>" "<name>" { ... }`

One policy decision targeting one or more endpoints. Three rule
types, each constrained to a matching endpoint family:

| Rule type | Endpoint families | Match facets |
|-----------|------------------|-------------|
| `http_rule` | `https` | `method` / `path` / `query` / `headers` / `body_json` / `body_contains` / `credential` |
| `sql_rule` | `sql` | `verb` / `tables` / `functions` / `statement` / `statement_regex` / `credential` |
| `k8s_rule` | `k8s` | `resource` / `verb` / `namespace` / `name` / `params` / `credential` |

Rule body shape:

```hcl
rule "http_rule" "stripe-extra-scrutiny" {
  endpoint = stripe                       # or `endpoints = [...]`
  priority = 100                          # >0 override, <0 catch-all, 0 default
  match    = {
    method = "POST"
    path   = ["/v1/refunds", "/v1/payouts", "/v1/transfers"]
  }
  approve = [billing-strict]              # or `verdict = "allow"|"deny"`
  reason  = "destructive money movement"  # surfaces in deny / dashboard
  # disabled = true                       # keep in source, skip eval
}
```

Match keys accept either a single string or a list (`any-of`
semantics). Strings starting with `!` are negated:

- `verb = ["create", "update", "patch"]` — any-of
- `name = "!debug-*"` — not glob
- `resource = ["!*/exec", "!*/attach"]` — none-of with negation per element
- `statement_regex = "(?i)\\b(secret|password|token)\\b"` — anchored PCRE

`credential = X` matches when the request was dispatched against the
named credential — useful for splitting approval policies per
credential on a multi-credential endpoint.

Approve chains:

```hcl
approve = [content-safety]                # bare ref → uses approver as-is
approve = [{ name = fast, policy = pg-secret-columns, cache_ttl = 600 }]
approve = [
  { name = content-safety, policy = reply-content },  # LLM stage
  support-ops,                                        # then human
]
```

### `profile "<name>" { endpoints = [...] }`

Endpoint membership list. A device gets exactly the endpoints its
profile names; rules ride along automatically because they're
attached to endpoints.

```hcl
profile "kaju" {
  endpoints = [
    github-kaju,
    slack-kaju,
    notion,           # shared with other profiles
    grafana,
    k8s-dev-ams,
  ]
}
```

### `device "<ip>" { rule ... ... { ... } }`

Per-device rule overrides — operator-edited from the dashboard's
per-device rule editor, splice into gateway.hcl as standalone blocks.
Each rule decodes through the same plugin pipeline as a top-level
rule; the compiler pins the rule to the device IP automatically and
adds a +1000 priority bump so device overrides win against
profile rules at the same explicit priority.

```hcl
device "10.55.0.2" {
  rule "http_rule" "deny-tinyclouds" {
    endpoint = github-api
    match    = { path = "/tinyclouds/*" }
    verdict  = "deny"
    reason   = "this device shouldn't reach tinyclouds"
  }

  rule "http_rule" "approve-deno-posts" {
    endpoint = deno
    match    = { method = "POST" }
    approve  = [dashboard]
    reason   = "POSTs to deno.com require approval"
  }
}
```

Notes:

- Rules inside `device {}` reference the device's IP implicitly. Do
  NOT add `peer_ip = ...` — the dispatcher handles peer scoping.
- An endpoint referenced by a device rule is auto-added to every
  profile's HostIndex so dispatch finds it. Other devices' traffic
  to those hosts gets MITM'd but no rule fires (the device-pinned
  rule's IP check filters per-peer at match time).
- The dashboard's per-device editor accepts `device {}` blocks
  alongside `endpoint`, `credential`, `approver`, and `policy` blocks
  — so AI-generated edits can introduce a new endpoint when the
  device rule needs it. Profiles, top-level rules, and `defaults`
  belong to the global gateway.hcl editor.

## Evaluation

Per request:

1. SNI / host (or postgres dst IP) → endpoint, scoped to the
   device's profile (`runtime.HostEndpoint`).
2. Endpoint's compiled rule list, sorted **descending by priority**,
   walked first-match-wins (`runtime.MatchRequest`).
3. Matched rule's `Outcome` dispatches:
   - `verdict = "allow"` — forward.
   - `verdict = "deny"` — 403 / postgres `ErrorResponse` with
     `reason`.
   - `approve = [...]` — pause, walk stages through
     `ApproverRuntime` (LLM via `policy` text + cache;
     human via Slack / dashboard with `human_timeout` ceiling).
4. On allow / hitl-allow, the credential plugin's
   `HTTPCredentialRuntime` / `PostgresCredentialRuntime` /
   `TLSCredentialRuntime` stamps the resolved secret onto the
   forwarded request.

Unknown hosts fall through to `defaults.unknown_host`
(`passthrough` by default).

## Plugin system

Each `(kind, type)` is owned by a plugin under `config/plugins/`.
Plugins call `config.Register` from their package's `init()`; the
`config/plugins/all` package blank-imports every built-in so a single
import from `main` pulls the registry.

A plugin declares:

- a Go struct (the `New` function returns a fresh decode target),
- `Refs []RefSpec` for bare-name fields the loader resolves
  against the symbol table,
- optional `Validate` for plugin-local invariants,
- `Build` which produces the canonical record stored in
  `Policy.<Kind>s[name]`,
- optional `CompileRule` (rule plugins only) that lowers the
  built record into a `*CompiledRule` at compile time,
- `Emit` for HCL round-tripping (dashboard whole-file edit goes
  through this),
- optional `Runtime` — type-asserted at request time against
  `HTTPCredentialRuntime` / `TLSCredentialRuntime` /
  `PostgresCredentialRuntime` / `ConnEndpointRuntime` /
  `PlaceholderDetector` / `ApproverRuntime` per kind.

`config/runtime/checker.go` validates that `Plugin.Runtime`, when
non-nil, satisfies the expected interface for its kind — catches
signature drift at init time instead of at first request.
