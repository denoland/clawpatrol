# Avocet rules (v14).
#
# Same semantics as v13. The version-history comments at the top of v13
# have been replaced with this documentation of what the format means
# and why it's shaped this way.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 1. WHAT THIS FILE IS                                             ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Avocet sits between an agent and the upstream services it talks to
# (GitHub, Slack, Postgres, Kubernetes, Stripe, ...). For every request
# the agent issues, Avocet does two things:
#
#   1. Inject the right credential into the request (replace a
#      placeholder header / cookie / SQL password with a real secret).
#   2. Apply policy rules: allow, deny with a reason, or route through
#      one or more approvers (LLM proctor and / or human-in-Slack).
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 2. TOP-LEVEL KINDS                                               ║
# ╚══════════════════════════════════════════════════════════════════╝
#
#   defaults     {}                       global fallbacks for fail-mode,
#                                         cache TTL, unknown-host policy
#
#   approver     "<type>" "<name>" {}     who arbitrates: llm_approver
#                                         (Claude proctor) or
#                                         human_approver (Slack channel)
#
#   policy       "<name>" {}              reusable LLM prompt text;
#                                         referenced from approve chains
#
#   credential   "<type>" "<name>" {}     a typed handle to a secret
#
#   endpoint     "<type>" "<name>" {}     a typed upstream binding:
#                                         hosts + connection config +
#                                         which credentials this
#                                         endpoint accepts.
#
#   rule         "<type>" "<name>" {}     one policy decision targeting
#                                         one or more endpoints. Types:
#                                         http_rule, sql_rule, k8s_rule.
#                                         A rule's predicate is a single
#                                         CEL expression in `condition`.
#
#   profile      "<name>" {}              endpoint membership list — a
#                                         user / agent identity
#                                         dispatches against exactly
#                                         the endpoints in its profile.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 3. RULES                                                         ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Each rule declares:
#
#   - which endpoint(s) it applies to (`endpoint = X` or
#     `endpoints = [X, Y, ...]`),
#   - an optional `credential = X` bare-name reference (request must
#     have been dispatched against that credential),
#   - an optional CEL `condition = "..."` predicate,
#   - one outcome: `verdict = "allow"`, `verdict = "deny"` (with
#     `reason`), or an `approve = [...]` chain.
#
# Per-family CEL variables:
#
#   http_rule  → method, path, query, headers, body, body_json
#   sql_rule   → verb, tables, functions, statement
#   k8s_rule   → resource, verb, ns, name, params
#
# Use the usual CEL builtins (in, startsWith, endsWith, contains,
# matches, size, ...) to express predicates.

defaults {
  unknown_host = "passthrough"
  llm_fail_mode = "closed"
  llm_cache_ttl = 300
  human_timeout = 600
  human_on_timeout = "deny"
}

# ── Approvers ────────────────────────────────────────

approver "llm_approver" "slack-block-kit-shape-judge" {
  model      = "claude-sonnet-4-20250514"
  credential = anthropic-avocet-sub
  policy     = slack-block-kit-shape
}
approver "llm_approver" "reply-content-judge" {
  model      = "claude-sonnet-4-20250514"
  credential = anthropic-avocet-sub
  policy     = reply-content
}
approver "llm_approver" "pg-secret-columns-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic-avocet-sub
  policy     = pg-secret-columns
}
approver "llm_approver" "pg-secret-named-defense-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic-avocet-sub
  policy     = pg-secret-named-defense
}
approver "llm_approver" "k8s-exec-content-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic-avocet-sub
  policy     = k8s-exec-content
}

approver "human_approver" "support-ops" {
  channel = "#agent-support"
  timeout = 86400
}
approver "human_approver" "console-dba"    { channel = "#agent-db" }
approver "human_approver" "scheduler-ops"  { channel = "#agent-db" }
approver "human_approver" "billing"        { channel = "#billing-approvals" }
approver "human_approver" "billing-strict" {
  channel           = "#billing-approvals"
  require_approvers = 2
}
approver "human_approver" "observability"  { channel = "#observability" }
approver "human_approver" "notion-archive" { channel = "#agent-notion" }

# ── Reusable LLM policy texts ───────────────────────

policy "slack-block-kit-shape" {
  text = <<-EOT
    The chat.postMessage body has a Block Kit message containing one
    or more buttons whose action_id starts with "approve_reply_". The
    reviewer in Slack must see what they're approving, and that text
    will be sent as plain-text email. Approve only if all of:

      1. A "Draft Reply" header block precedes the actions block.
      2. The next section block has non-empty text.
      3. After stripping leading/trailing ``` fences, that section
         text equals the button's `value` exactly.
      4. The button `value` contains no markdown — no [text](url),
         **bold**, __bold__, # heading, --- or *** rules.

    Otherwise DENY with a precise reason.
  EOT
}

policy "reply-content" {
  text = <<-EOT
    The JSON body has a `body` field containing a customer support
    reply. Apply these checks in order; deny on the first failure.

      (1) Salutation: deny if first line is a salutation. System
          auto-prepends "Hi <name>,". Apology / acknowledgment /
          substantive openers are fine.
      (2) Sign-off: deny if the very last line is a standalone
          sign-off. System auto-appends sign-off automatically.
      (3) Markdown: deny **bold**, __bold__, *italic*, _italic_,
          [text](url), # headings, --- / *** rules.
      (4) Content: deny offensive / abusive / impersonating /
          account-harming / empty / nonsensical content.
  EOT
}

policy "k8s-exec-content" {
  text = <<-EOT
    Inspect the kubectl exec command (each ?command= argv element).
    Deny if it dumps env vars (env, printenv, set, export, cat
    /proc/*/environ). Deny if it reads sensitive host-mount files
    (kubelet pod tokens, certs, private keys, kubeconfig,
    /etc/shadow, containerd/CRI sockets). Allow ls, ps, df, ip, ss,
    mount, dmesg, top, and apt-get install for debugging.
  EOT
}

policy "pg-secret-columns" {
  text = <<-EOT
    Deny if the SELECT projects (directly, via *, or via aggregates
    like json_agg / encode) any of:
      - github_identities.access_token or .refresh_token
      - tokens.hash
      - email_confirmations.token
      - authorizations.exchange_token, .code, .challenge
      - domain_certificates.private_key
      - database_instances.certificate
      - database_instances.connection_config password / secret keys
      - env_vars.value when is_secret = true (allow when restricted
        to is_secret = false explicitly)
    Allow reads of every other column.
  EOT
}

policy "pg-secret-named-defense" {
  text = <<-EOT
    Decide whether this SELECT actually returns secret data — i.e.
    it projects or aggregates a column whose name suggests a secret.
    Approve if the secret-named identifier appears only as a string
    literal or in a non-projected predicate.
  EOT
}

# ── Credentials ─────────────────────────────────────

credential "anthropic_manual_key" "anthropic-avocet-key" {
}
credential "anthropic_oauth_subscription" "anthropic-avocet-sub" {
}

credential "bearer_token" "github-avocet-pat" {}
credential "bearer_token" "github-kaju-pat"   {}
credential "bearer_token" "github-mira-pat"   {}

credential "slack_tokens" "slack-avocet-cred" {}
credential "slack_tokens" "slack-kaju-cred"   {}
credential "slack_tokens" "slack-mira-cred"   {}

credential "telegram_bot_token" "telegram-divy-cred" {}
credential "telegram_bot_token" "telegram-mira-cred" {}

credential "gemini_api_key" "gemini-mira-cred" {}

credential "openai_codex_oauth" "openai-codex-divy-cred" {}
credential "openai_codex_oauth" "openai-codex-mira-cred" {}

credential "bearer_token" "stripe-live-key" {
  idempotency_key = true
}
credential "bearer_token" "orb-test-key" {}
credential "bearer_token" "orb-prod-key" {}
credential "cookie_token" "deno-deploy-pat" {
  cookie_name = "session"
}
credential "postgres_credential" "pg-deployng-ro" {
  user        = "console_ro"
}
credential "postgres_credential" "pg-deployng-rw" {
  user        = "console"
}
credential "postgres_credential" "pg-scheduler-cred" {
  user        = "scheduler"
}

credential "notion_oauth" "notion-deno" {}
credential "bearer_token" "grafana-token" {}
credential "clickhouse_credential" "ch-o11y" {
  user = "avocet"
}
credential "mtls_credential" "k8s-dev-ams-mtls" {}
credential "mtls_credential" "k8s-dev-ord-mtls" {}
credential "aws_eks_credential" "k8s-eks-deployng-aws" {
  cluster = "deployng-prod"
  region  = "us-east-2"
  profile = "deployng-console-prod"
}

credential "bearer_token" "smithery-kaju"     {}
credential "bearer_token" "amem-kaju"         {}
credential "bearer_token" "checkly-kaju"      {}
credential "bearer_token" "posthog-kaju"      {}
credential "bearer_token" "deno-support-kaju" {}
credential "header_token" "honeycomb-kaju" {
  header = "x-honeycomb-team"
}
credential "header_token" "pagerduty-kaju" {
  header = "authorization"
  prefix = "Token token="
}

# ── Endpoints ────────────────────────────────────────

endpoint "https" "anthropic-avocet" {
  hosts = ["api.anthropic.com"]
  credentials = [
    { placeholder = "PH_anthropic_avocet_apikey", credential = anthropic-avocet-key },
    { placeholder = "PH_anthropic_avocet_subscription", credential = anthropic-avocet-sub },
  ]
}

endpoint "https" "github-avocet" {
  hosts       = ["api.github.com", "github.com"]
  credential = github-avocet-pat
}
endpoint "https" "github-kaju" {
  hosts       = ["api.github.com", "github.com"]
  credential = github-kaju-pat
}
endpoint "https" "github-mira" {
  hosts       = ["api.github.com", "github.com"]
  credential = github-mira-pat
}

endpoint "https" "slack-avocet" {
  hosts       = ["slack.com", "www.slack.com", "api.slack.com"]
  credential = slack-avocet-cred
}
endpoint "https" "slack-kaju" {
  hosts       = ["slack.com", "www.slack.com", "api.slack.com"]
  credential = slack-kaju-cred
}
endpoint "https" "slack-mira" {
  hosts       = ["slack.com", "www.slack.com", "api.slack.com"]
  credential = slack-mira-cred
}

endpoint "https" "telegram-divy" {
  hosts       = ["api.telegram.org"]
  credential = telegram-divy-cred
}
endpoint "https" "telegram-mira" {
  hosts       = ["api.telegram.org"]
  credential = telegram-mira-cred
}
endpoint "https" "gemini-mira" {
  hosts       = ["generativelanguage.googleapis.com"]
  credential = gemini-mira-cred
}
endpoint "https" "openai-codex-divy" {
  hosts       = ["chatgpt.com", "auth.openai.com"]
  credential = openai-codex-divy-cred
}
endpoint "https" "openai-codex-mira" {
  hosts       = ["chatgpt.com", "auth.openai.com"]
  credential = openai-codex-mira-cred
}

endpoint "https" "deno-deploy" {
  hosts       = ["console.deno.com"]
  credential = deno-deploy-pat
}
endpoint "https" "stripe" {
  hosts       = ["api.stripe.com"]
  credential = stripe-live-key
}
endpoint "https" "orb" {
  hosts = ["api.withorb.com"]
  credentials = [
    { placeholder = "PH_orb_test", credential = orb-test-key },
    { placeholder = "PH_orb_prod", credential = orb-prod-key },
  ]
}

endpoint "postgres" "pg-deployng" {
  host     = "deployng-prod.cluster-cnmc6k08siv7.us-east-2.rds.amazonaws.com:5432"
  database = "deployng"
  credentials = [
    { placeholder = "PH_pg_deployng_ro", credential = pg-deployng-ro },
    { placeholder = "PH_pg_deployng_rw", credential = pg-deployng-rw },
  ]
}
endpoint "postgres" "pg-scheduler" {
  host       = "scheduler-prod.cluster-cnmc6k08siv7.us-east-2.rds.amazonaws.com:5432"
  database   = "scheduler"
  credential = pg-scheduler-cred
}

endpoint "kubernetes" "k8s-eks-deployng-prod" {
  hosts       = ["*.gr7.us-east-2.eks.amazonaws.com"]
  description = "arn:aws:eks:us-east-2:050451385055:cluster/deployng-prod"
  credential = k8s-eks-deployng-aws
}

endpoint "https" "notion" {
  hosts       = ["api.notion.com", "mcp.notion.com"]
  credential = notion-deno
}
endpoint "https" "grafana" {
  hosts       = ["denoland.grafana.net"]
  credential = grafana-token
}
endpoint "clickhouse_https" "ch-o11y-https" {
  hosts       = ["clickhouse-o11y.tail9a48e.ts.net", "ch-o11y.infra.deno-gcp.net"]
  credential = ch-o11y
}
endpoint "clickhouse_native" "ch-o11y-native" {
  hosts       = ["clickhouse-o11y.tail9a48e.ts.net"]
  credential = ch-o11y
}
endpoint "kubernetes" "k8s-dev-ams" {
  server      = "209.250.247.66"
  ca_cert     = "<<file:k8s-dev-ams-ca.pem>>"
  description = "admin@net.deno-cluster.prod.vultr.ams"
  credential = k8s-dev-ams-mtls
}
endpoint "kubernetes" "k8s-dev-ord" {
  server      = "216.128.145.115"
  ca_cert     = "<<file:k8s-dev-ord-ca.pem>>"
  description = "admin@net.deno-cluster.prod.vultr.ord"
  credential = k8s-dev-ord-mtls
}

endpoint "https" "smithery" {
  hosts       = ["smithery.ai"]
  credential = smithery-kaju
}
endpoint "https" "amem" {
  hosts       = ["api.amem.ai"]
  credential = amem-kaju
}
endpoint "https" "checkly" {
  hosts       = ["api.checklyhq.com"]
  credential = checkly-kaju
}
endpoint "https" "posthog" {
  hosts       = ["us.i.posthog.com", "us.posthog.com"]
  credential = posthog-kaju
}
endpoint "https" "honeycomb" {
  hosts       = ["api.honeycomb.io"]
  credential = honeycomb-kaju
}
endpoint "https" "pagerduty" {
  hosts       = ["api.pagerduty.com"]
  credential = pagerduty-kaju
}
endpoint "https" "kaju-deno-support" {
  hosts       = ["support.deno.com"]
  credential = deno-support-kaju
}

# ── Rules ────────────────────────────────────────────

# ── Slack ───────────────────────────────────────────

rule "http_rule" "slack-avocet-approve-reply-shape" {
  endpoint  = slack-avocet
  condition = "method == 'POST' && path == '/api/chat.postMessage' && body.contains('approve_reply_')"
  approve   = [slack-block-kit-shape-judge]
}

# ── Deno Deploy ─────────────────────────────────────

rule "http_rule" "deno-deploy-reads" {
  endpoint  = deno-deploy
  condition = "method == 'GET'"
  verdict   = "allow"
}
rule "http_rule" "deno-deploy-ticket-mutations" {
  endpoint  = deno-deploy
  condition = "method == 'POST' && path in ['/api/trpc/admin.supportTickets.markAsSpam', '/api/trpc/admin.supportTickets.updateStatus']"
  approve   = [support-ops]
}
rule "http_rule" "deno-deploy-reply-on-behalf" {
  endpoint  = deno-deploy
  condition = "method == 'POST' && path == '/api/trpc/admin.supportTickets.replyOnBehalf'"
  approve   = [reply-content-judge, support-ops]
}
rule "http_rule" "deno-deploy-default" {
  endpoint = deno-deploy
  priority = -100
  verdict  = "deny"
  reason   = "console.deno.com mutations require an explicit approval rule"
}

# ── Stripe ──────────────────────────────────────────

rule "http_rule" "stripe-reads" {
  endpoint  = stripe
  condition = "method == 'GET'"
  verdict   = "allow"
}
rule "http_rule" "stripe-ephemeral-keys" {
  endpoint  = stripe
  priority  = 100
  condition = "method == 'POST' && path == '/v1/ephemeral_keys'"
  verdict   = "allow"
}
rule "http_rule" "stripe-no-deletes" {
  endpoint  = stripe
  condition = "method == 'DELETE'"
  verdict   = "deny"
  reason    = "Stripe deletes go through the approval flow as POST"
}
rule "http_rule" "stripe-extra-scrutiny" {
  endpoint  = stripe
  priority  = 100
  condition = "method == 'POST' && (path in ['/v1/refunds', '/v1/subscriptions', '/v1/subscription_items', '/v1/payouts', '/v1/transfers', '/v1/coupons', '/v1/promotion_codes'] || path.startsWith('/v1/charges/') && path.endsWith('/refund') || path.startsWith('/v1/subscriptions/') || path.startsWith('/v1/customers/') && path.endsWith('/subscriptions') || path.startsWith('/v1/invoices/') && (path.endsWith('/void') || path.endsWith('/finalize')))"
  approve   = [billing-strict]
}
rule "http_rule" "stripe-other-writes" {
  endpoint  = stripe
  condition = "method == 'POST'"
  approve   = [billing]
}
rule "http_rule" "stripe-default" {
  endpoint = stripe
  priority = -100
  verdict  = "deny"
}

# ── Orb ─────────────────────────────────────────────

rule "http_rule" "orb-test-allow-all" {
  endpoint   = orb
  credential = orb-test-key
  verdict    = "allow"
}
rule "http_rule" "orb-prod-reads" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "method == 'GET'"
  verdict    = "allow"
}
rule "http_rule" "orb-prod-no-deletes" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "method == 'DELETE'"
  verdict    = "deny"
  reason     = "Orb deletes go through approval flow as POST"
}
rule "http_rule" "orb-prod-writes" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "method in ['POST', 'PUT', 'PATCH']"
  approve    = [billing]
}

# ── Notion ──────────────────────────────────────────

rule "http_rule" "notion-reads" {
  endpoint  = notion
  condition = "method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "http_rule" "notion-search" {
  endpoint  = notion
  condition = "method == 'POST' && path == '/v1/search'"
  verdict   = "allow"
}
rule "http_rule" "notion-archive-route" {
  endpoint  = notion
  priority  = 100
  condition = "method == 'PATCH' && (path.startsWith('/v1/pages/') || path.startsWith('/v1/blocks/') || path.startsWith('/v1/databases/')) && body_json.archived == true"
  approve   = [notion-archive]
}
rule "http_rule" "notion-deletes" {
  endpoint  = notion
  condition = "method == 'DELETE'"
  approve   = [notion-archive]
}
rule "http_rule" "notion-create-update" {
  endpoint  = notion
  condition = "method in ['POST', 'PATCH']"
  verdict   = "allow"
}

# ── Grafana ─────────────────────────────────────────

rule "http_rule" "grafana-reads" {
  endpoint  = grafana
  condition = "method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "http_rule" "grafana-annotations-snapshots" {
  endpoint  = grafana
  condition = "method == 'POST' && path in ['/api/annotations', '/api/snapshots']"
  verdict   = "allow"
}
rule "http_rule" "grafana-no-destructive-deletes" {
  endpoint  = grafana
  condition = "method == 'DELETE' && (path.startsWith('/api/dashboards/') || path.startsWith('/api/datasources/') || path.startsWith('/api/folders/') || path.startsWith('/api/alert-rules/'))"
  verdict   = "deny"
  reason    = "Destructive deletes go through a PR, not the agent"
}
rule "http_rule" "grafana-dashboard-writes" {
  endpoint  = grafana
  condition = "method in ['POST', 'PUT', 'PATCH'] && (path.startsWith('/api/dashboards/') || path.startsWith('/api/datasources/') || path.startsWith('/api/folders/') || path.startsWith('/api/alert-rules/'))"
  approve   = [observability]
}

# ── ClickHouse ──────────────────────────────────────

rule "sql_rule" "clickhouse-reads" {
  endpoints = [ch-o11y-https, ch-o11y-native]
  condition = "verb in ['select', 'show', 'describe', 'explain', 'use']"
  verdict   = "allow"
}
rule "sql_rule" "clickhouse-default" {
  endpoints = [ch-o11y-https, ch-o11y-native]
  priority  = -100
  verdict   = "deny"
  reason    = "ClickHouse access is read-only"
}

# ── Postgres — banned across all postgres endpoints ─

rule "sql_rule" "pg-banned-verbs" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "verb in ['drop', 'truncate', 'alter', 'grant', 'revoke', 'vacuum', 'create', 'comment', 'do']"
  verdict   = "deny"
  reason    = "Schema changes / destructive DDL not permitted; use a migration PR"
}
rule "sql_rule" "pg-banned-functions" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "functions.exists(f, f in ['pg_terminate_backend', 'pg_cancel_backend', 'pg_read_file', 'pg_read_binary_file', 'lo_get']) || functions.exists(f, f.startsWith('dblink_'))"
  verdict   = "deny"
  reason    = "Disallowed function for agent access"
}
rule "sql_rule" "pg-banned-copy-from" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "statement.matches('(?is)copy.*from program')"
  verdict   = "deny"
  reason    = "COPY ... FROM PROGRAM is disallowed"
}
rule "sql_rule" "pg-banned-copy-to" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "statement.matches('(?is)copy.*to program')"
  verdict   = "deny"
  reason    = "COPY ... TO PROGRAM is disallowed"
}
rule "sql_rule" "pg-no-migrations" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "'kysely_migration' in tables"
  verdict   = "deny"
  reason    = "Migrations table is owned by the deploy pipeline"
}

# ── Postgres — pg-deployng-specific account rules ───

rule "sql_rule" "pg-deployng-ro-no-writes" {
  endpoint   = pg-deployng
  credential = pg-deployng-ro
  condition  = "verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  verdict    = "deny"
  reason     = "ro account is read-only — use the rw placeholder if you need to write"
}
rule "sql_rule" "pg-deployng-secret-columns" {
  endpoint  = pg-deployng
  priority  = 100
  condition = "verb == 'select' && tables.exists(t, t in ['github_identities', 'tokens', 'email_confirmations', 'authorizations', 'domain_certificates', 'database_instances', 'env_vars'])"
  approve   = [pg-secret-columns-judge]
}
rule "sql_rule" "pg-deployng-rw-writes" {
  endpoint   = pg-deployng
  credential = pg-deployng-rw
  condition  = "verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  approve    = [console-dba]
}
rule "sql_rule" "pg-deployng-reads" {
  endpoint  = pg-deployng
  condition = "verb in ['select', 'show', 'explain']"
  verdict   = "allow"
}
rule "sql_rule" "pg-deployng-default" {
  endpoint = pg-deployng
  priority = -100
  verdict  = "deny"
}

# ── Postgres — pg-scheduler-specific rules ──────────

rule "sql_rule" "pg-scheduler-secret-named-defense" {
  endpoint  = pg-scheduler
  priority  = 100
  condition = "verb == 'select' && statement.matches('(?i)\\\\b(secret|password|token|api_key|private_key|access_key|signing_secret)\\\\b')"
  approve   = [pg-secret-named-defense-judge]
}
rule "sql_rule" "pg-scheduler-writes" {
  endpoint  = pg-scheduler
  condition = "verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  approve   = [scheduler-ops]
}
rule "sql_rule" "pg-scheduler-reads" {
  endpoint  = pg-scheduler
  condition = "verb in ['select', 'show', 'explain']"
  verdict   = "allow"
}
rule "sql_rule" "pg-scheduler-default" {
  endpoint = pg-scheduler
  priority = -100
  verdict  = "deny"
}

# ── Kubernetes — base rules across all clusters ─────

rule "k8s_rule" "k8s-no-secrets" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 1000
  condition = "resource == 'secrets'"
  verdict   = "deny"
  reason    = "Secret values must not leave the cluster via the agent"
}
rule "k8s_rule" "k8s-no-interactive" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 1000
  condition = "resource in ['pods/exec', 'pods/attach'] && params.stdin == 'true'"
  verdict   = "deny"
  reason    = "Interactive shells can't be evaluated by the rules engine"
}
rule "k8s_rule" "k8s-no-disruptive" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "verb in ['drain', 'cordon', 'evict']"
  verdict   = "deny"
  reason    = "Cluster-disruptive operations are not allowed"
}
rule "k8s_rule" "k8s-no-portforward-non-debug" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 1000
  condition = "resource == 'pods/portforward' && !name.startsWith('debug-')"
  verdict   = "deny"
  reason    = "Port-forward only allowed to debug-* pods"
}
rule "k8s_rule" "k8s-no-mutations" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "verb in ['create', 'update', 'patch', 'delete'] && !name.startsWith('debug-') && !resource.endsWith('/exec') && !resource.endsWith('/attach') && !resource.endsWith('/portforward')"
  verdict   = "deny"
  reason    = "Only debug-* pods may be created / modified / deleted"
}
rule "k8s_rule" "k8s-exec-content-check" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 500
  condition = "resource == 'pods/exec'"
  approve   = [k8s-exec-content-judge]
}
rule "k8s_rule" "k8s-reads" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}
rule "k8s_rule" "k8s-debug-pods" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "verb in ['create', 'delete'] && resource == 'pods' && name.startsWith('debug-')"
  verdict   = "allow"
}
rule "k8s_rule" "k8s-exec-attach" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "verb in ['create', 'get'] && resource in ['pods/exec', 'pods/attach', 'pods/portforward']"
  verdict   = "allow"
}

# ── Kubernetes — EKS-specific extras ────────────────

rule "k8s_rule" "k8s-eks-no-runtime-writes" {
  endpoint  = k8s-eks-deployng-prod
  priority  = 1000
  condition = "verb in ['create', 'update', 'patch', 'delete'] && (ns in ['console', 'kube-system', 'cert-manager', 'external-secrets', 'argocd'] || ns.startsWith('flux'))"
  verdict   = "deny"
  reason    = "Writes to runtime namespaces would impact production"
}
rule "k8s_rule" "k8s-eks-no-legacy-secret-configmaps" {
  endpoint  = k8s-eks-deployng-prod
  priority  = 1000
  condition = "verb in ['get', 'list'] && resource == 'configmaps' && ns == 'console' && (name.endsWith('-secrets') || name.startsWith('env-'))"
  verdict   = "deny"
  reason    = "Some legacy configmaps still carry cleartext secrets"
}

# ── Kubernetes catch-alls (per cluster) ─────────────

rule "k8s_rule" "k8s-dev-ams-default" {
  endpoint = k8s-dev-ams
  priority = -100
  verdict  = "deny"
}
rule "k8s_rule" "k8s-dev-ord-default" {
  endpoint = k8s-dev-ord
  priority = -100
  verdict  = "deny"
}
rule "k8s_rule" "k8s-eks-default" {
  endpoint = k8s-eks-deployng-prod
  priority = -100
  verdict  = "deny"
}

# ── Profiles ────────────────────────────────────────

profile "avocet" {
  endpoints = [
    anthropic-avocet,
    github-avocet,
    slack-avocet,
    deno-deploy,
    stripe,
    orb,
    notion,
    grafana,
    pg-deployng,
    pg-scheduler,
    k8s-dev-ams,
    k8s-dev-ord,
    k8s-eks-deployng-prod,
    ch-o11y-https,
    ch-o11y-native,
  ]
}

profile "kaju" {
  endpoints = [
    github-kaju,
    slack-kaju,
    telegram-divy,
    openai-codex-divy,

    # shared with avocet:
    notion,
    grafana,
    ch-o11y-https,
    ch-o11y-native,
    k8s-dev-ams,
    k8s-dev-ord,

    # kaju's per-tool API access:
    smithery,
    amem,
    checkly,
    posthog,
    honeycomb,
    pagerduty,
    kaju-deno-support,
  ]
}

profile "mira" {
  endpoints = [
    github-mira,
    slack-mira,
    telegram-mira,
    gemini-mira,
    openai-codex-mira,

    # shared with kaju:
    openai-codex-divy,
  ]
}
