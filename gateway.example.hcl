# clawpatrol gateway config.
#
# Drop in /etc/clawpatrol/gateway.hcl, edit, run:
#
#     clawpatrol gateway -config /etc/clawpatrol/gateway.hcl
#
# Hot-reloadable: profile / ruleset / approver blocks + admin_email.
# Listen ports / ca_dir / oauth_dir / tailscale block need a restart.
#
# Concepts:
#   integrations — auth providers (claude, codex, github). Their hosts
#                  auto-MITM and inject OAuth tokens.
#   rules        — host-scoped policy, with match grammars per protocol
#                  (HTTP / Kubernetes / SQL).
#   rulesets     — named bundles of rules; profiles compose by name.
#   profiles     — bind integrations + rulesets + inline rules to
#                  onboarded devices. `extend = ["base"]` inherits.
#   approvers    — HITL notifiers. `dashboard` always-available.

listen      = "0.0.0.0:8443"
info_listen = "0.0.0.0:8080"
public_url  = "http://66.42.120.196:8080"
admin_email = "test@example.com"
ca_dir      = "/opt/clawpatrol/ca"
oauth_dir   = "/opt/clawpatrol/oauth"

gateway {
  control        = "wireguard"
  wg_endpoint    = "66.42.120.196:51820"
  wg_subnet_cidr = "10.55.0.0/24"
}

# -- profiles ---------------------------------------------------------

profile "default" {
  integrations = ["claude", "codex", "github"]
}

# profile "engineering" {
#   extend       = ["default"]
#   rules        = ["block-gh-push", "k8s-readonly"]
# }

# -- rulesets ---------------------------------------------------------
#
# Match grammar per protocol:
#
#   HTTP  : method, path, query, headers, body_json, body_contains
#   K8s   : resource, verb, namespace, name, params (path-derived)
#   SQL   : sql_verb, tables, function, statement, statement_regex,
#           account  (declared, but inert until postgres gateway lands)
#
# Glob patterns supported. Prefix a value with "!" to negate.

# ruleset "block-gh-push" {
#   rule {
#     host = "api.github.com"
#     match {
#       method    = ["POST"]
#       path      = "/repos/*/git/refs/heads/main"
#       body_json = { force = "true" }
#     }
#     action = "deny"
#     reason = "force-push to main goes through PR review"
#   }
# }

# ruleset "k8s-readonly" {
#   rule {
#     host = "k8s.example.com"
#     match { resource = ["secrets"] }
#     action = "deny"
#     reason = "secret values must not leave the cluster"
#   }
#   rule {
#     host = "k8s.example.com"
#     match {
#       resource = ["pods/exec", "pods/attach"]
#       params   = { stdin = "true" }
#     }
#     action = "deny"
#     reason = "no interactive shells"
#   }
#   rule {
#     host = "k8s.example.com"
#     match {
#       verb = ["create", "update", "patch", "delete"]
#       name = ["!debug-*"]
#     }
#     action = "deny"
#     reason = "only debug-* pods may be created / modified / deleted"
#   }
# }

# -- approvers --------------------------------------------------------

# approver "ops" {
#   type    = "slack"           # only "dashboard" is wired today;
#   channel = "#agent-ops"      # slack/llm reserved for plugins.
#   timeout = 600
# }
