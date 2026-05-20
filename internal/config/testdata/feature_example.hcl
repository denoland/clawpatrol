# clawpatrol gateway config.
#
# Copy this file somewhere on the gateway host (e.g.
# /opt/clawpatrol/gateway.hcl), edit the fields below, run:
#
#     clawpatrol gateway -config /opt/clawpatrol/gateway.hcl
#
# Hot-reloadable: every policy block + admin_email. Listen ports /
# state_dir / tailscale block need a restart.
#
# Top-level kinds:
#
#   defaults   {}                     global fallbacks for fail-mode,
#                                     cache TTL, unknown-host policy
#   approver   "<type>" "<name>"      who arbitrates (llm_approver |
#                                     human_approver). llm_approver
#                                     carries its prompt inline as
#                                     `policy = <<-EOT ... EOT`.
#   endpoint   "<type>" "<name>"      typed upstream binding (hosts +
#                                     connection params only)
#   credential "<type>" "<name>"      typed handle to a secret, bound
#                                     to the endpoint(s) it auths
#   rule       "<name>"               one policy decision targeting
#                                     one or more endpoints
#   profile    "<name>"               credential membership list — a
#                                     device's profile gets exactly
#                                     these credentials and (transitively)
#                                     the endpoints they bind
#
# References are bare names — no kind prefix. The flat namespace is
# globally unique; collisions are a load error.

# ── operational --------------------------------------------------------

listen      = "0.0.0.0:8443"
info_listen = "0.0.0.0:8080"
public_url  = "http://66.42.120.196:8080"
admin_email = "test@example.com"
log_path    = "/opt/clawpatrol/gateway.log"
state_dir   = "/opt/clawpatrol/oauth"

control        = "wireguard"
wg_endpoint    = "0.0.0.0:51820"
wg_subnet_cidr = "10.55.0.0/24"

# ── policy --------------------------------------------------------------

unknown_host     = "passthrough"
llm_fail_mode    = "closed"
llm_cache_ttl    = 300
human_timeout    = 600
human_on_timeout = "deny"

# Endpoints: hosts + protocol-family connection params. Pure network
# targets — credential binding lives on the credential block.

endpoint "https" "github" {
  hosts = ["api.github.com", "github.com"]
}

# Credentials: one per upstream secret. Each names the endpoint(s) it
# authenticates against; the actual secret value is stored separately
# in the gateway, keyed by name.

credential "bearer_token" "github" {
  endpoint = https.github
}

# Approvers: who arbitrates when a rule needs human / LLM review.

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

# Rules: family is inferred from each rule's endpoint(s). The
# condition's CEL variable is `http`, `sql`, or `k8s` accordingly.
# The rule's predicate is a single CEL expression in `condition`.

rule "github-reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  approve   = [human_approver.ops]
}

# Profiles: bind a device identity to a credential set. Endpoint
# membership rides along as the transitive closure
# profile → credentials → endpoints; rules attach to endpoints (so
# they ride along too).

profile "default" {
  credentials = [bearer_token.github]
}
