---
name: claw-patrol
title: Skill File
description: Set up and operate Claw Patrol, a firewall for AI agents. Write the gateway HCL config (credentials, endpoints, rules, approvers, profiles), run the gateway, onboard devices, wrap agent commands with `clawpatrol run`. Use when the user wants to install or operate Claw Patrol, write or modify a `gateway.hcl` policy, add allow / deny / approve rules over HTTPS / Postgres / Kubernetes / ClickHouse / SSH traffic, gate agent actions behind a human or an LLM judge, or debug Claw Patrol behavior.
---

# Claw Patrol

A firewall for AI agents. Two pieces: a **gateway** (Go binary on a
host you control — policy, credentials, audit log, dashboard) and
one or more **devices** (laptops, CI runners) that join the gateway
over WireGuard. Devices tunnel agent traffic to the gateway, which
per-request decides allow / deny / approve and injects the right
credential. The agent never holds the real credential.

```
Agent ─→ Device ──WireGuard──→ Gateway ──→ Upstream
                                  ├ matches rule
                                  ├ injects credential
                                  └ logs the action
```

## Install

Same binary, gateway + devices:

```
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

macOS / Linux on amd64 / arm64. Lands in `~/.local/bin/clawpatrol`.

## Run a gateway

Bootstrap (once):

```
clawpatrol gateway init
```

Detects the public IP, generates a CA, writes
`/etc/clawpatrol/gateway.hcl` (or `~/.clawpatrol/gateway.hcl` for
non-root), opens firewall ports, drops a systemd unit. Default
ports: `tcp/9080` dashboard, `tcp/8443` TLS gateway, `udp/51820`
WireGuard.

Then run:

```
systemctl enable --now clawpatrol-gateway       # systemd
clawpatrol gateway /etc/clawpatrol/gateway.hcl  # otherwise
```

Validate or regression-test a policy change:

```
clawpatrol validate gateway.hcl        # parse + compile
clawpatrol test gateway.hcl fixtures/  # replay recorded actions
```

## Write a config

`gateway.hcl` is HCL. Five labeled-block kinds (`credential`,
`endpoint`, `rule`, `profile`, `approver`) plus operational
top-level fields. Names share **one flat namespace** — references
are bare (`credential = github-pat`, never `credential.github-pat`).

### Minimal complete example

```hcl
admin_email      = "you@example.com"
dashboard_secret = "change-me-long-random"

control        = "wireguard"
wg_endpoint    = "1.2.3.4:51820"
wg_subnet_cidr = "10.55.0.0/24"

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

rule "github-reads" {
  endpoint  = github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint = github
  verdict  = "deny"
  priority = -100
  reason   = "writes go through PR review"
}

profile "default" { endpoints = [github] }
```

### Top-level fields

| Field | Notes |
|---|---|
| `admin_email` | Required. |
| `listen` | TLS gateway bind. Default `:443`. |
| `info_listen` | Dashboard + API bind. |
| `public_url` | Dashboard URL handed out at join time. |
| `dashboard_secret` | Required (or `insecure_no_dashboard_secret = true` for local testing). |
| `state_dir` | Directory holding `clawpatrol.db`. Defaults to `~/.clawpatrol/state`. |
| `control` | `"wireguard"` or `"tailscale"`. |
| `wg_endpoint` / `wg_subnet_cidr` | WG listener + device subnet. |
| `unknown_host` | `"passthrough"` (default) or `"deny"` for traffic no endpoint claims. |

Full list: [Config reference](/docs/config-reference/#top-level-fields).

### Credentials

Typed handle to a secret. HCL carries injection parameters only;
secret bytes live in the gateway's secret store (dashboard or
`CLAWPATROL_SECRET_<NAME>` env vars).

| Type | Injects |
|---|---|
| `bearer_token` | `Authorization: Bearer <token>` |
| `header_token` | `<header>: <prefix><token>` |
| `cookie_token` | `Cookie: <name>=<token>` |
| `mtls_credential` | Client cert + key |
| `postgres_credential` | SCRAM / cleartext password |
| `clickhouse_credential` | ClickHouse user/password |
| `ssh` | SSH private key (+ passphrase, host pubkey) |
| `anthropic_oauth_subscription` | Claude.ai OAuth (auto-refreshed) |
| `openai_codex_oauth` | Codex / ChatGPT OAuth |
| `github_oauth` | GitHub OAuth device flow |
| `slack_tokens` | Bot + signing-secret for Slack notifier |

Full list: [Config reference](/docs/config-reference/#credential-blocks).

### Endpoints

Typed upstream binding. Type determines the family (`http`, `sql`,
`k8s`), which determines the CEL variables rules can read.

| Type | Family | Required |
|---|---|---|
| `https` | `http` | `hosts` |
| `openai_codex_https` | `http` | `hosts` (specialized for ChatGPT Codex) |
| `kubernetes` | `k8s` | `server` or `hosts` |
| `postgres` | `sql` | `host`, `database` |
| `clickhouse_native` | `sql` | `hosts` |
| `clickhouse_https` | `sql` | `hosts` |
| `ssh` | (no rules) | `hosts` |

All take `credential = <name>` or
`credentials = [{user=..., credential=...}, ...]` for per-user
dispatch (SSH, Postgres).

### Rules

```hcl
rule "<name>" {
  endpoint  = <endpoint>          # or endpoints = [a, b]
  priority  = 100                 # higher fires first; default 0
  condition = "<CEL>"             # absent = match everything
  verdict   = "allow"             # or "deny"
  # OR: approve = [<approver>, ...]
  reason    = "..."
}
```

Family is inferred from the rule's endpoint(s); mixing families is
a load error.

Outcome — exactly one of `verdict = "allow"`, `verdict = "deny"`,
or `approve = [a, b, c]` (each approver runs in order; all must
allow).

Matching: rules sorted by `priority` descending, first match wins.
Declaration order is the tiebreaker. Default-deny catch-all:
`priority = -100, verdict = "deny"`.

### CEL variables

**`http.*`** (HTTPS endpoints)

| Variable | Type |
|---|---|
| `method` | string (lowercased; `'POST'` in rule source works too) |
| `path` | string |
| `query` / `headers` | `map<string, list<string>>` |
| `body` | string |
| `body_json` | parsed JSON; access fields directly |

**`sql.*`** (postgres / clickhouse)

| Variable | Type |
|---|---|
| `verb` | string (lowercased) — `'select'`, `'insert'`, `'drop'`, … |
| `tables` / `functions` | `list<string>` (lowercased) |
| `statement` | string (raw SQL) |

**`k8s.*`**

| Variable | Type |
|---|---|
| `verb` | string (lowercased) — `'get'`, `'create'`, `'delete'`, … |
| `resource` / `namespace` / `name` | string |
| `params` | `map<string, string>` (URL query) |

Full idioms: [Approval rules](/docs/approval-rules/).

### Rule examples

Deny destructive SQL:

```hcl
rule "pg-no-destructive" {
  endpoints = [pg-writer, pg-reader]
  condition = "sql.verb in ['drop', 'truncate', 'alter', 'grant', 'revoke']"
  verdict   = "deny"
}
```

Allow k8s reads, gate writes behind a human:

```hcl
rule "k8s-reads" {
  endpoint  = k8s-prod
  condition = "k8s.verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}

rule "k8s-writes" {
  endpoint  = k8s-prod
  condition = "k8s.verb in ['create', 'update', 'patch', 'delete']"
  approve   = [ops]
}
```

LLM-then-human gating for sensitive reads:

```hcl
policy "no-pii-exfil" {
  text = "Approve unless the query reads PII without a WHERE id = clause."
}

approver "llm_approver" "judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = claude
  policy     = no-pii-exfil
}

approver "human_approver" "dba" { channel = "#dba" }

rule "pg-sensitive-read" {
  endpoint  = pg-reader
  condition = "sql.verb == 'select' && 'users' in sql.tables"
  approve   = [judge, dba]
}
```

### Profiles

Each device gets one profile at approval time. The profile names
the endpoints whose rules apply to that device's traffic.

```hcl
profile "default" { endpoints = [github, pg-reader, k8s-dev] }
profile "trusted" { endpoints = [github, pg-writer, k8s-dev, k8s-prod] }
```

### Approvers

```hcl
approver "human_approver" "ops" {
  channel    = "#agent-ops"   # via the credential's notifier
  credential = slack-ops      # omit for dashboard-only
  timeout    = 600
}

approver "llm_approver" "judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = claude
  policy     = no-pii-exfil   # references a `policy "<name>" {}` block
}
```

Built-in approver `dashboard` parks pending items on the dashboard
without paging.

## Onboard a device

```
clawpatrol join http://<gateway-host>:9080
```

Prints a one-time code; operator confirms it in the dashboard,
assigns a profile, approves. Persists the WG conf to
`~/.config/clawpatrol/wg.conf`, installs the gateway CA, adds
`eval "$(clawpatrol env)"` to your shell rc.

Flags: `--hostname`, `--profile`, `--whole-machine` (route every
packet through the gateway instead of just `clawpatrol run`),
`--no-trust` (skip system trust install).

macOS first join: approve the Network Extension in **System
Settings → Privacy & Security**.

## Run an agent

```
clawpatrol run -- claude
clawpatrol run -- gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

The wrapped process's traffic routes through the gateway. The agent
sees a normal network — no proxy URL, no CA bundle.

- **Linux**: unprivileged user namespace + private WG tunnel per
  invocation.
- **macOS**: Network Extension captures by PID.

## State layout

**Gateway** (`/etc/clawpatrol/` root, or `~/.clawpatrol` non-root):

```
gateway.hcl                  # operator-edited
<state_dir>/clawpatrol.db    # everything else — CA material, WG keys,
                             # devices, sessions, audit log
```

`state_dir` defaults to `<data-dir>/oauth/` for `gateway init`-created
hosts (legacy layout, still works). The CA cert + key, WireGuard
server key, SSH host keys, telemetry UUID, and DNS-VIP allocations
all live inside `clawpatrol.db` — nothing else on disk.

**Device:**

```
~/.clawpatrol/ca.crt
~/.config/clawpatrol/wg.conf
```

## Common errors

| Error | Fix |
|---|---|
| `config file "X" does not exist` | Pass a real path or run `clawpatrol gateway init` first. |
| `endpoint "X" not in compiled policy` | Fixture pins a stale endpoint name. Regenerate via dashboard "Download action". |
| `host "X" is claimed by multiple endpoints` | Set `match.endpoint` in the fixture to disambiguate. |
| `mixed-family endpoint set` | A rule's `endpoints` list mixes families (e.g. HTTPS + Postgres). Split the rule. |
| Dashboard "misconfiguration" page | Set `dashboard_secret` (or `insecure_no_dashboard_secret = true` for testing). |
| Agent gets `tls: unknown authority` | Device's `~/.clawpatrol/ca.crt` isn't trusted. Re-run `clawpatrol join` or trust manually. |

## Deeper

[Architecture](/docs/architecture/) — interception + dispatch.
[Approval rules](/docs/approval-rules/) — CEL idioms + approver
chains. [Config reference](/docs/config-reference/) — every HCL
attribute. [CLI](/docs/cli/) — every subcommand.
[Security model](/docs/security-model/) — threat model.
[`clawpatrol-test`](/docs/clawpatrol-test/) — fixtures + CI.
