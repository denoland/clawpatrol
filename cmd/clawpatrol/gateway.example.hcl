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
#   endpoint   "<type>" "<name>"      typed network target (hosts +
#                                     connection params only)
#   credential "<type>" "<name>"      typed handle to a secret, bound
#                                     to the endpoint(s) it auths
#   rule       "<name>"               one policy decision targeting
#                                     one or more endpoints
#   profile    "<name>"               credential membership list — a
#                                     device's profile gets exactly
#                                     these credentials and (transitively)
#                                     the endpoints they bind
#   tunnel     "<type>" "<name>"      side-process the gateway dials
#                                     through (e.g. cloud-sql-proxy)
#
# References are bare names — no kind prefix. The flat namespace is
# globally unique; collisions are a load error.

# ── operational --------------------------------------------------------

info_listen = "127.0.0.1:8080"
public_url  = "https://gw.example.com"
admin_email = "you@example.com"
state_dir   = "/opt/clawpatrol"

# `listen` (TLS MITM listener) is omitted: in WireGuard mode the
# gateway routes agent TLS through the WG netstack, not through this
# socket. Set it only in Tailscale mode (where it's the tsnet
# listener on the tailnet IP).

# Dashboard auth: there is no HCL field. The first time you open
# the dashboard you set a "root" password; it lives bcrypt-hashed in
# clawpatrol.db. To skip the web first-run or rotate later, run:
#
#   clawpatrol gateway --set-dashboard-password '<password>' gateway.hcl
#   clawpatrol gateway --reset-dashboard-password gateway.hcl
#
# In tailscale mode you can additionally allowlist operator tailnet
# logins so they get in without typing the password. Tagged devices
# (agents) never match a wildcard entry — they have no user login.
#
#   dashboard_operators = ["alice@example.com", "*@example.com"]

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

# ── endpoints ---------------------------------------------------------
#
# Pure network targets: hosts + protocol-family connection params.
# No credential refs — credential binding lives on the credential
# blocks below. The endpoint family (https / ssh / postgres /
# clickhouse_native / kubernetes) determines what protocol the
# gateway speaks and which CEL variable rules see (`http`, `sql`,
# `k8s`).

# HTTPS — AI providers.
endpoint "https" "anthropic"  { hosts = ["api.anthropic.com"] }
endpoint "https" "openai-api" { hosts = ["api.openai.com"] }
endpoint "openai_codex_https" "openai-chatgpt" {
  hosts = ["chatgpt.com"]
}

# HTTPS — SaaS.
endpoint "https" "github-api" {
  hosts = [
    "api.github.com",
    "raw.githubusercontent.com",
    "github.com",
  ]
}
endpoint "https" "slack" {
  hosts = [
    "slack.com",
    "api.slack.com",
    "wss-primary.slack.com",
  ]
}
endpoint "https" "notion"  { hosts = ["api.notion.com", "mcp.notion.com"] }
endpoint "https" "grafana" { hosts = ["mygrafana.grafana.net"] }

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
  hosts = ["build.internal.example.com:22"]
}

# Postgres — wire-protocol native. Agent dials `host:port`; the
# gateway terminates Postgres on both halves and parses each SQL
# statement so `rule` blocks can pattern-match via `sql.*`.
#
# One endpoint, two credentials: readonly and writer share the same
# upstream server. The postgres user is the dispatch discriminator —
# the gateway picks the credential whose `user` matches the agent's
# StartupMessage user. Rules below use `credential = pg-writer`
# to gate writes; reads run through `pg-readonly` and bypass
# the write-only rules.
endpoint "postgres" "pg" {
  host = "pg.internal.example.com:5432"
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
}

# Kubernetes — `server` is the apiserver IP the gateway intercepts
# (the kubeconfig you mint for the agent points at this IP). The
# gateway terminates TLS, decodes the request, and exposes verb /
# resource / name via `k8s.*` to rules.
endpoint "kubernetes" "k8s-dev"  { server = "198.51.100.10" }
endpoint "kubernetes" "k8s-prod" { server = "198.51.100.11" }

# ── credentials -------------------------------------------------------
#
# One per upstream secret. Each names the endpoint(s) it
# authenticates against; the body lists only injection parameters.
# The actual secret value is stored separately keyed by name (paste
# it via the dashboard).

# AI providers — three common shapes.
#
#   anthropic_oauth_subscription — Claude Pro/Max subscription. The
#     binary handles the OAuth flow at first dashboard visit.
#   anthropic_manual_key         — raw API key from console.anthropic.com.
#     Use this when you also need to call the API from your own
#     rules (the llm_approver below).
#   openai_codex_oauth           — ChatGPT subscription OAuth, mirrors
#     what `codex` and `chatgpt.com` use.
credential "anthropic_oauth_subscription" "claude" {
  endpoint = https.anthropic
}
# Same `anthropic` endpoint, different credential type. Both bind to
# the one network target; `anthropic-key` is wielded only by the
# llm_approver below (the gateway's outbound), `claude` rides on user
# profiles — they're never wielded in the same profile, so no
# dispatch placeholder is needed.
credential "anthropic_manual_key" "anthropic-key" {
  endpoint = https.anthropic
}
# codex auths against both the OpenAI API endpoint and the
# chatgpt.com surface — list-form `endpoints` covers both.
credential "openai_codex_oauth" "codex" {
  endpoints = [https.openai-api, openai_codex_https.openai-chatgpt]
}
credential "github_oauth" "github" {
  endpoint = https.github-api
}

# Bearer tokens — opaque "Authorization: Bearer <token>".
credential "bearer_token" "grafana" {
  endpoint = https.grafana
}

# Notion OAuth — workspace-scoped.
credential "notion_oauth" "notion" {
  endpoint = https.notion
}

# Slack — used both as a regular endpoint (chat.postMessage etc) and
# as the channel for human_approver interactive approvals below.
credential "slack_tokens" "slack" {
  endpoint = https.slack
}

# SSH — private key + (optional) passphrase + (optional) host_pubkey
# live in the secret store. Paste them via the dashboard.
credential "ssh_key" "build-host" {
  endpoint = ssh.build-host
}

# Database credentials are user-scoped: the upstream sees the value
# of `user`; the password lives in the secret store. The same
# postgres endpoint carries two credentials — the agent's
# StartupMessage user picks which one the gateway injects.
credential "postgres_credential" "pg-readonly" {
  endpoint = postgres.pg
  user     = "agent_ro"
}
credential "postgres_credential" "pg-writer" {
  endpoint = postgres.pg
  user     = "agent_rw"
}
credential "clickhouse_credential" "ch-analytics" {
  endpoint = clickhouse_native.ch-analytics
  user     = "agent"
}

# Kubernetes — client cert + key (mTLS) per cluster.
credential "mtls_credential" "k8s-dev"  { endpoint = kubernetes.k8s-dev }
credential "mtls_credential" "k8s-prod" { endpoint = kubernetes.k8s-prod }

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
  credential  = slack_tokens.slack
  interactive = true
  timeout     = 600
}

# Long-running human approval — useful for rules where the human
# may be off-hours and you'd rather wait than auto-deny.
approver "human_approver" "support-ops" {
  channel     = "#agent-support"
  credential  = slack_tokens.slack
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
  credential = anthropic_manual_key.anthropic-key
  policy     = policy.no-pii-columns
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
  endpoint  = https.github-api
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "github-writes" {
  endpoint  = https.github-api
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  approve   = [human_approver.ops]
}

# Postgres — layered defense. All rules attach to the single `pg`
# endpoint; the `credential = pg-writer` predicate scopes
# writer-only rules to traffic dispatched against that credential.
#
#   1. Hard deny: DDL / GRANT / REVOKE / VACUUM. (any credential)
#   2. Hard deny: filesystem-reaching helpers.   (any credential)
#   3. PII judge: reads of users / api_tokens routed through the LLM.
#   4. Writer-only writes: human approval.
#   5. Plain reads: allow.
#   6. Catch-all: deny.
rule "pg-banned-verbs" {
  endpoint = postgres.pg
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
  endpoint = postgres.pg
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
  endpoint  = postgres.pg
  priority  = 50
  condition = <<-CEL
    sql.verb == 'select'
    && sets.intersects(sql.tables, ['users', 'api_tokens'])
  CEL
  approve = [llm_approver.no-pii-judge]
}
rule "pg-writes" {
  endpoint   = postgres.pg
  credential = postgres_credential.pg-writer
  condition  = "sql.verb in ['insert', 'update', 'delete', 'merge']"
  approve    = [human_approver.support-ops]
}
rule "pg-reads" {
  endpoint  = postgres.pg
  condition = "sql.verb in ['select', 'show', 'explain', 'describe']"
  verdict   = "allow"
}
rule "pg-default" {
  endpoint = postgres.pg
  priority = -100
  verdict  = "deny"
  reason   = "Unknown SQL verb — explicit allow rule required"
}

# Kubernetes — reads anywhere; mutations only against debug-* pods;
# secret values never leave the cluster; no interactive shells (the
# rule engine can't evaluate stdin streams).
rule "k8s-no-secrets" {
  endpoints = [kubernetes.k8s-dev, kubernetes.k8s-prod]
  priority  = 1000
  condition = "k8s.resource == 'secrets'"
  verdict   = "deny"
  reason    = "Secret values must not leave the cluster via the agent"
}
rule "k8s-no-interactive" {
  endpoints = [kubernetes.k8s-dev, kubernetes.k8s-prod]
  priority  = 1000
  condition = <<-CEL
    k8s.resource in ['pods/exec', 'pods/attach']
    && k8s.params.stdin == 'true'
  CEL
  verdict = "deny"
  reason  = "Interactive shells can't be evaluated by the rules engine"
}
rule "k8s-reads" {
  endpoints = [kubernetes.k8s-dev, kubernetes.k8s-prod]
  condition = "k8s.verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}
rule "k8s-debug-pods" {
  endpoints = [kubernetes.k8s-dev, kubernetes.k8s-prod]
  condition = <<-CEL
    k8s.verb in ['create', 'delete']
    && k8s.resource == 'pods'
    && k8s.name.startsWith('debug-')
  CEL
  verdict = "allow"
}
rule "k8s-default" {
  endpoints = [kubernetes.k8s-dev, kubernetes.k8s-prod]
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
#   host   = "instance.synthetic.example:5432"
#   tunnel = csql
# }
#
# credential "postgres_credential" "csql-cred" {
#   endpoint = pg-cloud
#   user     = "service-account@project.iam"
#   database = "main"
# }

# ── profiles ----------------------------------------------------------
#
# Bind a device identity to a credential set. Endpoint membership
# rides along as the transitive closure profile → credentials →
# endpoints; rules attach to endpoints (so they ride along too).
# Every enrolled device gets exactly one profile; "default" is the
# fallback the dashboard assigns at approval time.

profile "default" {
  credentials = [anthropic_oauth_subscription.claude, openai_codex_oauth.codex, github_oauth.github]
}

profile "support" {
  credentials = [anthropic_oauth_subscription.claude, github_oauth.github, slack_tokens.slack, notion_oauth.notion]
}

profile "data" {
  credentials = [
    anthropic_oauth_subscription.claude,
    github_oauth.github,
    postgres_credential.pg-readonly,
    clickhouse_credential.ch-analytics,
  ]
}

profile "platform" {
  credentials = [
    anthropic_oauth_subscription.claude,
    github_oauth.github,
    slack_tokens.slack,
    postgres_credential.pg-writer,
    ssh_key.build-host,
    mtls_credential.k8s-dev,
    mtls_credential.k8s-prod,
  ]
}
