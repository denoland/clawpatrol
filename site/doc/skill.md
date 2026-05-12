# Skill

Everything an operator (or an LLM agent) needs to set up Claw
Patrol, write a policy, and route traffic through it. Self-contained
quick reference; link out to the detail pages when something needs
depth.

## What Claw Patrol is

A firewall for AI agents. Two pieces:

- **Gateway** — a Go binary on a host you control. Holds the
  policy, the credentials, the audit log, and the dashboard.
- **Devices** — your laptop, a CI runner — that join the gateway
  over WireGuard. They tunnel the agent's outbound flows to the
  gateway, which decides per request what to allow, deny, or gate
  behind a human, and which credential to inject.

The agent never holds the real credential. The gateway never trusts
the agent.

```
Agent ─→ Device ──WireGuard──→ Gateway ──→ Upstream
                                  │
                                  ├ matches rule
                                  ├ injects credential
                                  └ logs the action
```

---

## Install

Same binary on the gateway host and every device:

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

macOS / Linux, amd64 / arm64. `~/.local/bin/clawpatrol`.

---

## Run a gateway

### Bootstrap (once per host)

```bash
clawpatrol gateway init
```

Detects the public IP, generates a CA, writes
`/etc/clawpatrol/gateway.hcl` (or `~/.clawpatrol/gateway.hcl` for
non-root), opens firewall ports, drops a systemd unit, prints the
next-step command.

Defaults:

| Port | Use |
|---|---|
| `udp/51820` | WireGuard listener |
| `tcp/9080` | Dashboard + HTTP API |
| `tcp/8443` | TLS gateway (host-local; doesn't need to be public) |

### Run

```bash
systemctl enable --now clawpatrol-gateway     # systemd hosts
clawpatrol gateway /etc/clawpatrol/gateway.hcl    # otherwise
```

Dashboard at `http://<gateway-host>:9080`.

### Validate / test policy changes

```bash
clawpatrol validate gateway.hcl                # parse + compile
clawpatrol test gateway.hcl fixtures/          # replay recorded actions
```

See [`clawpatrol-test`](clawpatrol-test) for the fixture format.

---

## Write a config

`gateway.hcl` is HCL with five labeled-block kinds plus a handful of
operational top-level fields. Names share **one flat namespace** —
references are bare names, never `kind.name`.

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

profile "default" {
  endpoints = [github]
}
```

This compiles, runs, and gates a GitHub PAT behind a read-only
policy.

### Top-level fields (operational)

The ones you'll actually set:

| Field | Notes |
|---|---|
| `admin_email` | Required. Operator contact. |
| `listen` | TLS gateway bind. Default `:443`. |
| `info_listen` | Dashboard + API bind. |
| `public_url` | Dashboard URL handed out at join time. |
| `dashboard_secret` | Required (or set `insecure_no_dashboard_secret = true` for local testing). |
| `ca_dir` | Where the CA lives. |
| `oauth_dir` | Where the SQLite state DB lives. |
| `control` | `"wireguard"` (default) or `"tailscale"`. |
| `wg_endpoint`, `wg_subnet_cidr` | WireGuard listener + device subnet. |
| `unknown_host` | `"passthrough"` (default) or `"deny"` — what to do with traffic not claimed by any endpoint. |

Full list: [Config reference › Top-level fields](/docs/config-reference/#top-level-fields).

### Credentials

A typed handle to a secret. The HCL carries only injection
parameters; secret bytes live in the gateway's secret store
(populated via the dashboard or `CLAWPATROL_SECRET_<NAME>` env
vars).

Common types:

| Type | Injects |
|---|---|
| `bearer_token` | `Authorization: Bearer <token>` |
| `header_token` | `<header>: <prefix><token>` (configurable `header`, `prefix`) |
| `cookie_token` | `Cookie: <name>=<token>` |
| `mtls_credential` | Client cert + key for the TLS handshake |
| `postgres_credential` | SCRAM / cleartext password for Postgres |
| `clickhouse_credential` | ClickHouse user/password |
| `ssh` | SSH private key + optional passphrase + host pubkey |
| `anthropic_oauth_subscription` | Claude.ai OAuth token (refreshed automatically) |
| `openai_codex_oauth` | Codex / ChatGPT OAuth token |
| `github_oauth` | GitHub PAT via OAuth device flow |
| `slack_tokens` | Bot + signing-secret bundle for Slack notifier |

Full list: [Config reference › `credential` blocks](/docs/config-reference/#credential-blocks).

### Endpoints

A typed upstream binding. The endpoint type determines the protocol
family (`http`, `sql`, `k8s`) which determines which CEL variables
rules can read.

| Type | Family | Required fields |
|---|---|---|
| `https` | `http` | `hosts = [...]` |
| `openai_codex_https` | `http` | `hosts = [...]` (specialized for ChatGPT Codex's two-transport flow) |
| `kubernetes` | `k8s` | `server` or `hosts` |
| `postgres` | `sql` | `host`, `database` |
| `clickhouse_native` | `sql` | `hosts = [...]` |
| `clickhouse_https` | `sql` | `hosts = [...]` |
| `ssh` | (no rules) | `hosts = [...]` |

All take `credential = <name>` (or `credentials = [{user=..., credential=...}, ...]` for per-user dispatch on SSH and Postgres).

### Rules

One rule per policy decision. The protocol family is inferred from
the rule's endpoint(s); mixing families in one rule is a load error.

```hcl
rule "<name>" {
  endpoint  = <endpoint-name>           # or endpoints = [a, b, c]
  priority  = 100                       # higher fires first; default 0
  condition = "<CEL expression>"        # absent = match everything
  verdict   = "allow"                   # or "deny"
  # OR: approve = [<approver-name>, ...]
  reason    = "human-readable explanation"
}
```

**Outcome — pick exactly one:**

- `verdict = "allow"` — forward the request after credential injection.
- `verdict = "deny"` — refuse, with `reason` in the error to the agent.
- `approve = [a, b, c]` — route through each approver in order; **all** must allow.

**Matching:** rules within an endpoint are sorted by `priority` descending; first match wins. Declaration order is the tiebreaker. Default-deny catch-all is `priority = -100, verdict = "deny"`.

### CEL variables by family

**HTTPS** (`http.*`)

| Variable | Type |
|---|---|
| `http.method` | string, lowercased — `'GET'` and `'get'` both work |
| `http.path` | string |
| `http.query` | `map<string, list<string>>` |
| `http.headers` | `map<string, list<string>>` |
| `http.body` | string (raw bytes) |
| `http.body_json` | parsed JSON; access fields directly (e.g. `http.body_json.archived == true`) |

**SQL** (`sql.*`, for postgres / clickhouse)

| Variable | Type |
|---|---|
| `sql.verb` | string, lowercased — `'select'`, `'insert'`, `'drop'`, … |
| `sql.tables` | `list<string>`, lowercased |
| `sql.function` | `list<string>`, lowercased — function calls in the statement |
| `sql.statement` | string (raw SQL, no case folding) |

**k8s** (`k8s.*`)

| Variable | Type |
|---|---|
| `k8s.verb` | string, lowercased — `'get'`, `'list'`, `'create'`, `'delete'`, … |
| `k8s.resource` | string |
| `k8s.namespace` | string |
| `k8s.name` | string |
| `k8s.params` | `map<string, string>` (single-valued URL query params) |

Full details + idioms: [Approval rules](/docs/approval-rules/).

### Rule examples

Deny destructive Postgres verbs cluster-wide:

```hcl
rule "pg-no-destructive" {
  endpoints = [pg-writer, pg-reader]
  condition = "sql.verb in ['drop', 'truncate', 'alter', 'grant', 'revoke']"
  verdict   = "deny"
}
```

Allow k8s reads but gate writes behind a human:

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

Gate `SELECT *` from a sensitive table through an LLM judge then a human:

```hcl
policy "no-pii-exfil" {
  text = "Approve unless the query reads PII (emails, names, ssns) without a WHERE id = clause."
}

approver "llm_approver" "judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = claude
  policy     = no-pii-exfil
}

approver "human_approver" "dba" {
  channel = "#dba"
}

rule "pg-sensitive-read" {
  endpoint  = pg-reader
  condition = "sql.verb == 'select' && 'users' in sql.tables"
  approve   = [judge, dba]
}
```

### Profiles

A profile is a named endpoint list. Each device gets exactly one
profile at approval time; that profile's endpoints are what its
traffic can reach (subject to the rules attached to those
endpoints).

```hcl
profile "default" {
  endpoints = [github, pg-reader, k8s-dev]
}

profile "trusted" {
  endpoints = [github, pg-writer, k8s-dev, k8s-prod]
}
```

### Approvers

Two types:

```hcl
approver "human_approver" "ops" {
  channel    = "#agent-ops"   # Slack/Discord/Telegram channel (via the credential)
  credential = slack-ops      # optional; omit for dashboard-only
  timeout    = 600            # seconds; falls back to human_on_timeout
}

approver "llm_approver" "judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = claude
  policy     = no-pii-exfil   # reusable prompt from a policy "<name>" {} block
}
```

A rule's `approve = [a, b, c]` runs each in order; all must allow.
The bare name `dashboard` is a built-in approver that parks pending
items on the dashboard without paging anyone.

---

## Onboard a device

On the device:

```bash
clawpatrol join http://<gateway-host>:9080
```

- Prints a one-time code. Operator opens the dashboard, confirms
  the code, assigns a profile, approves.
- WireGuard conf persisted at `~/.config/clawpatrol/wg.conf`.
- Gateway CA fetched into the system trust store.
- `eval "$(clawpatrol env)"` added to your shell rc.

**Flags worth knowing:**

| Flag | Effect |
|---|---|
| `--hostname NAME` | Device name shown in the dashboard. Default: OS hostname. |
| `--profile NAME` | Profile to suggest at approval time. |
| `--whole-machine` | Bring up `wg-quick` and route every packet through the gateway. Default: persist conf only, use `clawpatrol run` per-process. |
| `--no-trust` | Fetch the CA but skip system trust install. |

macOS: first join prompts for the Network Extension in **System
Settings → Privacy & Security**.

---

## Run an agent

```bash
clawpatrol run -- claude
clawpatrol run -- gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

The wrapped process's traffic routes through the gateway. The
agent sees a normal network — no proxy URL, no CA bundle, no
configuration.

- **Linux**: unprivileged user namespace + private WireGuard tunnel
  per invocation. Concurrent `clawpatrol run`s don't share an
  identity.
- **macOS**: Network Extension captures by PID. First run after
  install needs the extension approved in System Settings.

---

## Where things live

**Gateway host** (set up by `gateway init`):

```
/etc/clawpatrol/          # root install — or ~/.clawpatrol non-root
  gateway.hcl             # HCL config
  ca/ca.crt
  ca/ca.key
  oauth/clawpatrol.db     # SQLite — devices, sessions, audit log
  oauth/wg-server.key
```

**Device** (set up by `join`):

```
~/.clawpatrol/
  ca.crt                  # gateway CA
~/.config/clawpatrol/
  wg.conf                 # WireGuard config
```

---

## Common errors

| Error | Fix |
|---|---|
| `config file "X" does not exist` | Pass a real path, or run `clawpatrol gateway init` first. |
| `endpoint "X" not in compiled policy` | The fixture pins an endpoint name that no longer exists. Regenerate via the dashboard "Download action" button. |
| `host "X" is claimed by multiple endpoints` | Set `match.endpoint` in the fixture to disambiguate. |
| Rule loads with `mixed-family endpoint set` | A rule's `endpoints = [a, b]` references endpoints with different families (e.g. an HTTPS and a Postgres endpoint). Split the rule. |
| Dashboard "misconfiguration" page | Set `dashboard_secret` in `gateway.hcl` (or `insecure_no_dashboard_secret = true` for testing only). |
| Agent gets `tls: unknown authority` errors | The device's `~/.clawpatrol/ca.crt` isn't in your trust store. Re-run `clawpatrol join` (or trust the cert manually). |

---

## Going deeper

- [Architecture](/docs/architecture/) — how interception and dispatch actually work.
- [Approval rules](/docs/approval-rules/) — full CEL idioms + approver chains.
- [Config reference](/docs/config-reference/) — every HCL attribute.
- [CLI](/docs/cli/) — every subcommand and flag.
- [Security model](/docs/security-model/) — threat model + what's out of scope.
- [`clawpatrol-test`](/docs/clawpatrol-test/) — fixture format + CI integration.
