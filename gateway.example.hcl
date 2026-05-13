# clawpatrol gateway config.
#
# Drop in /etc/clawpatrol/gateway.hcl, edit, run:
#
#     clawpatrol gateway /etc/clawpatrol/gateway.hcl
#
# Hot-reloadable: every policy block + admin_email. Listen ports /
# state_dir / tailscale block need a restart.
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
#
# References are bare names — no kind prefix. The flat namespace is
# globally unique; collisions are a load error.

# ── operational --------------------------------------------------------

listen      = "0.0.0.0:8443"
info_listen = "0.0.0.0:8080"
public_url  = "http://66.42.120.196:8080"
admin_email = "test@example.com"
state_dir   = "/opt/clawpatrol/oauth"

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
wg_endpoint    = "66.42.120.196:51820"
wg_subnet_cidr = "10.55.0.0/24"

# ── policy defaults ----------------------------------------------------

unknown_host     = "passthrough"
llm_fail_mode    = "closed"
llm_cache_ttl    = 300
human_timeout    = 600
human_on_timeout = "deny"

# Credentials: one per upstream secret. The body lists only injection
# parameters; the actual secret is stored separately keyed by name.

credential "bearer_token" "github-pat" {}

# Endpoints: hosts + which credential the agent uses against them.

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = github-pat
}

# ClickHouse over the native protocol. `tls = true` enables TLS on
# the upstream hop. `accept_invalid_certificate = true` (mirrors
# clickhouse-client's flag) skips upstream cert validation — use for
# self-hosted ClickHouse fronted by a private CA; trusts whatever
# cert the upstream presents. Default keeps full cert validation
# against system roots.
#
# credential "clickhouse_credential" "ch-self-hosted" {}
# endpoint "clickhouse_native" "ch-self-hosted" {
#   hosts                      = ["clickhouse.internal:9440"]
#   tls                        = true
#   accept_invalid_certificate = true
#   credential                 = ch-self-hosted
# }

# Approvers: who arbitrates when a rule needs human / LLM review.

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

# Rules: family is inferred from each rule's endpoint(s). The
# condition's CEL variable is `http`, `sql`, or `k8s` accordingly.

rule "github-reads" {
  endpoint  = github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = github
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  approve   = [ops]
}

# SSH endpoints. The wire protocol carries no SNI / Host header, so
# the gateway runs a DNS server inside the WG tunnel and answers
# A/AAAA queries for SSH-able hostnames with virtual IPs from
# 10.78.0.0/16 and fd78::/64. When the client connects to the VIP
# the gateway recovers the hostname, terminates SSH on both halves,
# and uses the credential below for upstream auth.
#
# VIPs are persisted in sqlite so they survive restarts AND policy
# reloads — clients' cached DNS answers stay valid through gateway
# hops. Each SSH endpoint also gets its own persisted host key
# (also in sqlite, via the plugin blob store) on first use; add the
# printed fingerprint to the user's known_hosts file (the dashboard
# surfaces it per endpoint).

credential "ssh" "build-host-cred" {
  # private_key + (optional) passphrase + (optional) host_pubkey live
  # in the secret store — paste them via the dashboard.
}

endpoint "ssh" "build-host" {
  hosts      = ["build.example.com:2222"]
  credential = build-host-cred
  # The agent's username (`ssh user@build.example.com`) is passed
  # through to the upstream verbatim. For per-username dispatch use
  # `credentials = [{user="root", credential=...}, {credential=...}]`
  # — last entry without `user` is the catchall.
}

# Profiles: bind a device identity to an endpoint set. Rules ride along
# automatically because they're attached to endpoints.

profile "default" {
  endpoints = [github, build-host]
}
