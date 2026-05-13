# clawpatrol gateway config.
#
# Copy this file somewhere on the gateway host (e.g.
# /opt/clawpatrol/gateway.hcl), edit the fields below, run:
#
#     clawpatrol gateway /opt/clawpatrol/gateway.hcl
#
# Hot-reloadable: every policy block + admin_email. Listen ports /
# state_dir / control block need a restart.
#
# Labeled blocks:
#
#   approver   "<type>" "<name>"      who arbitrates (llm_approver |
#                                     human_approver)
#   policy     "<name>"               reusable LLM proctor prompt
#   credential "<type>" "<name>"      typed handle to a secret
#   endpoint   "<type>" "<name>"      typed upstream binding
#   rule       "<name>"               one policy decision targeting
#                                     one or more endpoints
#   profile    "<name>"               endpoint membership list — a
#                                     device's profile gets exactly
#                                     these endpoints
#   tunnel     "<type>" "<name>"      side-process the gateway dials
#                                     through (e.g. cloud-sql-proxy)
#
# References are bare names — no kind prefix. The flat namespace is
# globally unique; collisions are a load error.

# ── operational --------------------------------------------------------

listen      = "0.0.0.0:8443"
info_listen = "0.0.0.0:8080"
public_url  = "https://gw.example.com"
admin_email = "you@example.com"
state_dir   = "/opt/clawpatrol"

# Dashboard auth — pick exactly one. The gateway refuses to serve the
# dashboard / APIs until one of these is set, to avoid silently
# exposing it on a public network.
#
#   dashboard_secret = "<long random string>"   # production
#   insecure_no_dashboard_secret = true         # testing only — anyone
#                                               # who can reach the
#                                               # dashboard URL gets in
dashboard_secret = "change-me-to-a-long-random-string"

control        = "wireguard"
wg_subnet_cidr = "10.55.0.0/24"

# wg_endpoint is optional. Server-side it's listen address + port
# (default 0.0.0.0:51820). Clients dial `host(public_url):port`, so
# you only set wg_endpoint when you need a different host for WG
# than for the dashboard (split-host deployments) or a non-default
# port. Examples:
#   wg_endpoint = ":41820"            # default host, custom port
#   wg_endpoint = "wg.example.com:51820"   # WG host != dashboard host

# ── policy defaults ---------------------------------------------------

unknown_host     = "passthrough"
llm_fail_mode    = "closed"
llm_cache_ttl    = 300
human_timeout    = 600
human_on_timeout = "deny"

# ── credentials -------------------------------------------------------
#
# One per upstream secret. The body lists only injection parameters;
# the actual secret is stored separately keyed by name (paste it via
# the dashboard).

# AI providers — three common shapes.
#
#   anthropic_oauth_subscription — Claude Pro/Max subscription. The
#     binary handles the OAuth flow at first dashboard visit.
#   anthropic_manual_key         — raw API key from console.anthropic.com.
#     Use this when you also need to call the API from your own
#     rules (the llm_approver below).
#   openai_codex_oauth           — ChatGPT subscription OAuth, mirrors
#     what `codex` and `chatgpt.com` use.
credential "anthropic_oauth_subscription" "claude"        {}
credential "anthropic_manual_key"         "anthropic-key" {}
credential "openai_codex_oauth"           "codex"         {}
credential "github_oauth"                 "github"        {}

# Bearer tokens — opaque "Authorization: Bearer <token>".
credential "bearer_token" "grafana-token" {}

# Notion OAuth — workspace-scoped.
credential "notion_oauth" "notion-oauth" {}

# Cookie-based auth — for upstreams (typically internal web apps)
# that authenticate by session cookie.
credential "cookie_token" "internal-dashboard" {
  cookie_name = "session"
}

# Slack — used both as a regular endpoint (chat.postMessage etc) and
# as the channel for human_approver interactive approvals below.
credential "slack_tokens" "slack-token" {}

# SSH — private key + (optional) passphrase + (optional) host_pubkey
# live in the secret store. Paste them via the dashboard.
credential "ssh" "build-host-cred" {}

# Database credentials are user-scoped: the upstream sees the value
# of `user`; the password lives in the secret store.
credential "postgres_credential"   "pg-readonly-cred"  { user = "agent" }
credential "postgres_credential"   "pg-writer-cred"    { user = "agent" }
credential "clickhouse_credential" "ch-analytics-cred" { user = "agent" }

# Kubernetes — client cert + key (mTLS) per cluster.
credential "mtls_credential" "k8s-dev-mtls"  {}
credential "mtls_credential" "k8s-prod-mtls" {}

# ── endpoints ---------------------------------------------------------
#
# Hosts the agent is allowed to dial, plus which credential gets
# injected on each upstream call. The endpoint family (https / ssh
# / postgres / clickhouse_native / kubernetes) determines what
# protocol the gateway speaks and which CEL variable rules see
# (`http`, `sql`, `k8s`).

# HTTPS — AI providers.
endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  credential = claude
}
endpoint "https" "anthropic-api" {
  hosts      = ["api.anthropic.com"]
  credential = anthropic-key
}
endpoint "https" "openai-api" {
  hosts      = ["api.openai.com"]
  credential = codex
}
endpoint "openai_codex_https" "openai-chatgpt" {
  hosts      = ["chatgpt.com"]
  credential = codex
}

# HTTPS — SaaS.
endpoint "https" "github-api" {
  hosts = [
    "api.github.com",
    "raw.githubusercontent.com",
    "github.com",
  ]
  credential = github
}
endpoint "https" "slack" {
  hosts = [
    "slack.com",
    "api.slack.com",
    "wss-primary.slack.com",
  ]
  credential = slack-token
}
endpoint "https" "notion" {
  hosts      = ["api.notion.com", "mcp.notion.com"]
  credential = notion-oauth
}
endpoint "https" "grafana" {
  hosts      = ["mygrafana.grafana.net"]
  credential = grafana-token
}

# SSH — the wire protocol carries no SNI / Host header, so the
# gateway runs a DNS server inside the WG tunnel and answers A/AAAA
# queries for SSH-able hostnames with virtual IPs from 10.78.0.0/16
# and fd78::/64. When the client connects to the VIP the gateway
# recovers the hostname, terminates SSH on both halves, and uses
# the credential below for upstream auth.
#
# VIPs are persisted in sqlite so they survive restarts AND policy
# reloads — clients' cached DNS answers stay valid through gateway
# hops. Each SSH endpoint also gets its own persisted host key (in
# sqlite); the dashboard surfaces the fingerprint to paste into
# known_hosts.
endpoint "ssh" "build-host" {
  hosts      = ["build.internal.example.com:22"]
  credential = build-host-cred
  # The agent's username (`ssh user@build.internal.example.com`) is
  # passed through verbatim. For per-username dispatch, use
  # `credentials = [{user="root", credential=...}, {credential=...}]`
  # — the last entry without `user` is the catchall.
}

# Postgres — wire-protocol native. Agent dials `host:port`; the
# gateway terminates Postgres on both halves and parses each SQL
# statement so `rule` blocks can pattern-match via `sql.*`.
endpoint "postgres" "pg-readonly" {
  host       = "pg.internal.example.com:5432"
  database   = "appdb"
  credential = pg-readonly-cred
}
endpoint "postgres" "pg-writer" {
  host       = "pg.internal.example.com:5432"
  database   = "appdb"
  credential = pg-writer-cred
}

# ClickHouse — over the native protocol. `tls = true` enables TLS
# upstream; `accept_invalid_certificate = true` (mirrors
# clickhouse-client's flag) skips upstream cert validation — use
# this for self-hosted ClickHouse fronted by a private CA. Default
# keeps full cert validation against system roots.
endpoint "clickhouse_native" "ch-analytics" {
  hosts                      = ["clickhouse.internal.example.com:9440"]
  tls                        = true
  accept_invalid_certificate = true
  credential                 = ch-analytics-cred
}

# Kubernetes — `server` is the apiserver IP the gateway intercepts
# (the kubeconfig you mint for the agent points at this IP). The
# gateway terminates TLS, decodes the request, and exposes verb /
# resource / name via `k8s.*` to rules.
endpoint "kubernetes" "k8s-dev" {
  server     = "198.51.100.10"
  credential = k8s-dev-mtls
}
endpoint "kubernetes" "k8s-prod" {
  server     = "198.51.100.11"
  credential = k8s-prod-mtls
}

# ── approvers ---------------------------------------------------------
#
# A rule with `approve = [a, b, c]` runs each approver in sequence;
# any "deny" denies, "allow" passes to the next, the last allow
# admits. Approvers compose: put cheap LLM checks first, expensive
# humans last.

# Interactive Slack approval — the bot posts an Approve / Deny
# message in `channel`. interactive=true wires up the buttons.
approver "human_approver" "ops" {
  channel     = "#agent-ops"
  credential  = slack-token
  interactive = true
  timeout     = 600
}

# Long-running human approval — useful for rules where the human
# may be off-hours and you'd rather wait than auto-deny.
approver "human_approver" "support-ops" {
  channel     = "#agent-support"
  credential  = slack-token
  interactive = true
  timeout     = 86400 # 24h
}

# LLM judges — a single-purpose proctor prompt wrapped as an
# approver. The model is invoked through `anthropic-key` (the
# manual key credential above).
policy "no-pii-columns" {
  text = <<-EOT
    Deny if the SELECT projects (directly, via *, via aggregates,
    or via a JSONB extract that returns the underlying value) any
    of:

      - users.email
      - users.phone_number
      - api_tokens.hash

    A column name appearing only in a WHERE predicate (and not in
    the projection) is fine. SELECT count(*) is fine.
  EOT
}

approver "llm_approver" "no-pii-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic-key
  policy     = no-pii-columns
}

# ── rules -------------------------------------------------------------
#
# Family is inferred from each rule's endpoint(s) — the condition's
# CEL variable is `http`, `sql`, or `k8s` accordingly. Rule
# precedence: hard-deny rules first (higher `priority`), specific
# allows next, catch-all deny at the bottom (negative `priority`).
# Within the same priority the first matching rule wins.

# HTTPS — read-only allow, mutations through human approval.
rule "github-reads" {
  endpoint  = github-api
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "github-writes" {
  endpoint  = github-api
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  approve   = [ops]
}

# Postgres — layered defense.
#
#   1. Hard deny: DDL / GRANT / REVOKE / VACUUM.
#   2. Hard deny: filesystem-reaching helpers.
#   3. PII judge: reads of users / api_tokens routed through the LLM.
#   4. Other writes: human approval.
#   5. Plain reads: allow.
#   6. Catch-all: deny.
rule "pg-banned-verbs" {
  endpoint = pg-writer
  priority = 100
  condition = <<-CEL
    sql.verb in [
      'drop', 'truncate', 'alter', 'grant', 'revoke',
      'create', 'comment', 'do', 'vacuum',
    ]
  CEL
  verdict = "deny"
  reason  = "Schema changes land via migration PR, not via the agent"
}
rule "pg-banned-functions" {
  endpoint = pg-writer
  priority = 100
  condition = <<-CEL
    sets.intersects(sql.functions, [
      'pg_read_file', 'pg_read_binary_file', 'lo_get',
    ])
    || sql.functions.exists(f, f.startsWith('dblink_'))
  CEL
  verdict = "deny"
  reason  = "Filesystem-reaching functions are off-limits"
}
rule "pg-pii-read" {
  endpoint  = pg-writer
  priority  = 50
  condition = <<-CEL
    sql.verb == 'select'
    && sets.intersects(sql.tables, ['users', 'api_tokens'])
  CEL
  approve = [no-pii-judge]
}
rule "pg-writes" {
  endpoint  = pg-writer
  condition = "sql.verb in ['insert', 'update', 'delete', 'merge']"
  approve   = [support-ops]
}
rule "pg-reads" {
  endpoint  = pg-writer
  condition = "sql.verb in ['select', 'show', 'explain', 'describe']"
  verdict   = "allow"
}
rule "pg-default" {
  endpoint = pg-writer
  priority = -100
  verdict  = "deny"
  reason   = "Unknown SQL verb — explicit allow rule required"
}

# Kubernetes — reads anywhere; mutations only against debug-* pods;
# secret values never leave the cluster; no interactive shells (the
# rule engine can't evaluate stdin streams).
rule "k8s-no-secrets" {
  endpoints = [k8s-dev, k8s-prod]
  priority  = 1000
  condition = "k8s.resource == 'secrets'"
  verdict   = "deny"
  reason    = "Secret values must not leave the cluster via the agent"
}
rule "k8s-no-interactive" {
  endpoints = [k8s-dev, k8s-prod]
  priority  = 1000
  condition = <<-CEL
    k8s.resource in ['pods/exec', 'pods/attach']
    && k8s.params.stdin == 'true'
  CEL
  verdict = "deny"
  reason  = "Interactive shells can't be evaluated by the rules engine"
}
rule "k8s-reads" {
  endpoints = [k8s-dev, k8s-prod]
  condition = "k8s.verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}
rule "k8s-debug-pods" {
  endpoints = [k8s-dev, k8s-prod]
  condition = <<-CEL
    k8s.verb in ['create', 'delete']
    && k8s.resource == 'pods'
    && k8s.name.startsWith('debug-')
  CEL
  verdict = "allow"
}
rule "k8s-default" {
  endpoints = [k8s-dev, k8s-prod]
  priority  = -100
  verdict   = "deny"
}

# ── tunnels (optional) ------------------------------------------------
#
# Side-processes the gateway launches and dials through. Useful for
# cloud-sql-proxy, IAP, an SSH bastion forward, etc. The example
# below wires a Cloud SQL Postgres reached through cloud-sql-proxy
# v2 (IAM auth). The agent dials a synthetic hostname; DNS-VIP
# intercepts; the gateway routes through the local proxy listener.
#
# credential "postgres_credential" "csql-cred" {
#   user = "service-account@project.iam"
# }
#
# tunnel "local_command" "csql" {
#   command = [
#     "/usr/local/bin/cloud-sql-proxy",
#     "--auto-iam-authn",
#     "--credentials-file", "/opt/clawpatrol/secrets/sa.json",
#     "project:region:instance?port=5433",
#   ]
#   listen        = "127.0.0.1:5433"
#   ready_probe   = "tcp"
#   ready_timeout = "30s"
#   share         = "singleton"
#   keepalive     = "10m"
# }
#
# endpoint "postgres" "pg-cloud" {
#   host       = "instance.synthetic.example:5432"
#   database   = "main"
#   tunnel     = csql
#   credential = csql-cred
# }

# ── profiles ----------------------------------------------------------
#
# Bind a device identity to an endpoint set. Rules ride along
# automatically because they're attached to endpoints. Every
# enrolled device gets exactly one profile; "default" is the
# fallback the dashboard assigns at approval time.

profile "default" {
  endpoints = [anthropic, openai-api, openai-chatgpt, github-api]
}

profile "support" {
  endpoints = [anthropic, github-api, slack, notion]
}

profile "data" {
  endpoints = [
    anthropic,
    github-api,
    pg-readonly,
    ch-analytics,
  ]
}

profile "platform" {
  endpoints = [
    anthropic,
    github-api,
    slack,
    pg-writer,
    build-host,
    k8s-dev,
    k8s-prod,
  ]
}
