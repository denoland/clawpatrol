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
# This file describes both jobs in one document. It is lowered to flat
# tables in unclaw's SQLite store at load time (see the `tools/avocet-
# config` lowerer); nothing in this file is interpreted at request
# time, only the lowered rows are.
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
#                                         (bearer_token, mtls_credential,
#                                         postgres_credential, ...).
#                                         The actual secret value lives
#                                         in unclaw's credential store,
#                                         keyed by name.
#
#   endpoint     "<type>" "<name>" {}     a typed upstream binding:
#                                         hosts + connection config +
#                                         which credentials this
#                                         endpoint accepts.
#                                         Types: https, postgres,
#                                         kubernetes, clickhouse_https,
#                                         clickhouse_native.
#
#   rule         "<name>" {}              one policy decision targeting
#                                         one or more endpoints. The
#                                         rule's family is inferred from
#                                         its endpoint set and pins the
#                                         CEL variable bound in the
#                                         `condition` expression.
#
#   profile      "<name>" {}              endpoint membership list — a
#                                         user / agent identity
#                                         dispatches against exactly
#                                         the endpoints in its profile.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 3. NAMES AND REFERENCES                                          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Single flat namespace. Every named entity (endpoint, credential,
# rule, approver, policy, profile) shares one namespace; names must be
# globally unique.
#
# References are bare names — no kind prefix, no type prefix:
#
#     endpoint    = pg-deployng              # not  postgres.pg-deployng
#     credentials = [github-avocet-pat]      # not  credential.bearer_token...
#     approve     = [fast]                   # not  approver.llm_approver.fast
#
# The two-label declaration (`endpoint "https" "github-avocet"`)
# carries type information for the loader's schema validation, but
# reference syntax doesn't repeat it. The loader resolves a bare name
# by looking across all kinds; collisions are a load error.
#
# Note: ClickHouse exposes two protocols (HTTPS API + native binary)
# from the same upstream cluster, so two endpoints share the upstream:
# `ch-o11y-https` and `ch-o11y-native`. Same upstream, two rows,
# distinct names.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 4. ENDPOINT → CREDENTIAL BINDING                                 ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Endpoints declare which credentials they accept. Two binding shapes:
#
#   (a) Singular, no-placeholder:
#
#         endpoint "https" "github-avocet" {
#           hosts      = ["api.github.com", "github.com"]
#           credential = github-avocet-pat
#         }
#
#       The agent sends the request as-is (whatever Authorization
#       header it has, or none); Avocet replaces it with the real
#       secret before forwarding upstream. This is the common case.
#
#   (b) Multi-credential dispatch via placeholder:
#
#         endpoint "https" "orb" {
#           hosts = ["api.withorb.com"]
#           credentials = [
#             { placeholder = "PH_orb_test", credential = orb-test-key },
#             { placeholder = "PH_orb_prod", credential = orb-prod-key },
#           ]
#         }
#
#       The agent picks which credential it wants by sending the
#       matching placeholder string in the Authorization header (or
#       password field, for postgres). At inject time, Avocet swaps
#       the placeholder for the matching credential's real secret.
#       Used when the same upstream service has multiple credentials
#       with materially different blast radius — orb test vs prod, or
#       postgres ro vs rw — and the agent needs to declare which one.
#
# Equivalences:
#
#     credential = orb-test-key
#       ≡  credentials = [{ credential = orb-test-key }]
#       ≡  credentials = [{ credential = orb-test-key, placeholder = null }]
#
# Mixing (a) and (b): a `credentials = [...]` list MAY contain a
# trailing entry without a `placeholder`. That entry is the
# "no-placeholder" fallback — the runtime tries each placeholder-keyed
# entry first; if no agent placeholder matches, the no-placeholder
# entry is used. The exact "no-placeholder" semantic is
# plugin-defined: HTTPS overwrites Authorization regardless of what the
# agent sent; postgres swaps the agent's password for the real one.
#
# v14 has 3 multi-credential endpoints: anthropic-avocet (api-key +
# oauth), orb (test + prod), pg-deployng (ro + rw). The other 28
# endpoints use the singular form.
#
# Why placeholders live on the binding, not the credential:
#
#   - The same credential could in principle be reused at multiple
#     endpoints with different placeholder strings.
#   - The placeholder is a property of "how this endpoint advertises
#     a choice to the agent," which is a per-endpoint concern, not a
#     property of the secret itself.
#   - Credentials become pure secret references — dropping them or
#     renaming them doesn't ripple through to the rule grammar.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 5. RULES                                                         ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Each rule is a top-level resource (PagerDuty / AWS LB style). It
# declares:
#
#   - which endpoint(s) it applies to (`endpoint = X` or
#     `endpoints = [X, Y, ...]`),
#   - an optional `credential = X` bare-name reference (request
#     must have been dispatched against that credential),
#   - an optional CEL `condition = "..."` predicate,
#   - one outcome: `verdict = "allow"`, `verdict = "deny"` (with
#     `reason`), or an `approve = [...]` chain.
#
# Why top-level rules, not nested under endpoints:
#
#   - Cross-endpoint rules (k8s-no-secrets across three clusters,
#     pg-banned-verbs across both postgres servers) can name the
#     full endpoint list directly: `endpoints = [a, b, c]`. No
#     duplication; no inheritance machinery.
#   - Each rule has one obvious place. `grep '"k8s-no-secrets"'`
#     finds it.
#   - The data shape matches what unclaw stores (a flat
#     `approval_rules` table scoped per integration), so no clever
#     compilation step is required at load.
#
# Family inference. `rule "<name>"` — one block kind, no type
# label. The rule's protocol family is inferred from its endpoint(s)
# at load time and pins the CEL variables available to the condition
# (a rule targeting a postgres endpoint sees the `sql` variable, not
# `http`). A rule's referenced endpoints must all be of the same
# protocol family, or it's a load error.
#
#   https endpoints  → `http` variable
#   postgres,
#   clickhouse_https,
#   clickhouse_native → `sql` variable
#   kubernetes       → `k8s` variable
#
# Evaluation. For each request, the runtime collects all rules that
# (1) name the request's endpoint and (2) are not `disabled = true`.
# It sorts by `priority` descending and walks the list; the first
# rule whose `credential` (if set) matches and whose CEL `condition`
# evaluates true decides the outcome. First-match-wins. An absent
# or empty `condition` matches every request.
#
# Priority is a single signed integer:
#
#   priority > 0     "override" — wins over default-priority rules
#   priority = 0     default (the field is omitted)
#   priority < 0     "fallback" — runs after every >= 0 rule
#
# When to set priority:
#
#   - Don't, by default. If two rules have mutually-exclusive matches
#     (different methods, different paths, different credentials),
#     evaluation order doesn't matter — leave them at priority 0.
#
#   - Use a positive priority when a narrower rule needs to win over
#     a broader rule with a different outcome. Example:
#     `stripe-extra-scrutiny` (priority 100) routes a curated list of
#     destructive paths to the stricter `billing-strict` approver,
#     overriding `stripe-other-writes` (priority 0) which would
#     otherwise send everything to the lenient `billing` approver.
#
#   - Use a negative priority for catch-all / default-deny rules.
#     Example: `deno-deploy-default` (priority -100) denies everything
#     not matched by an earlier explicit rule. Negative priorities
#     replace the older `catch_all = true` flag — same semantic, one
#     dimension.
#
# v14 distribution: 11 rules with positive priority (overrides),
# 8 with negative priority (catch-alls), 35 at default 0.
#
# Disabled rules. `disabled = true` keeps a rule in source for audit
# / rollback without removing it. Lowers to `enabled = 0`.
#
# Per-family CEL variables. Each family exposes one struct-typed
# top-level variable; fields are accessed with dot notation.
#
#   https → http.method, http.path, http.query, http.headers,
#           http.body, http.body_json
#   sql   → sql.verb, sql.tables, sql.function, sql.statement
#   k8s   → k8s.verb, k8s.resource, k8s.namespace, k8s.name,
#           k8s.params
#
# `verb` (sql, k8s) and `method` (http) are unary strings. `tables`
# and `function` (sql) are list[string]; `query` and `headers`
# (http) are map[string]list[string]; `params` (k8s) is
# map[string]string. `body` is the raw request body as string;
# `body_json` is its parsed-JSON shape (dyn).
#
# CEL idioms used throughout this file:
#
#   - Membership / exact-or-any-of: `sql.verb in ['select', 'show']`,
#     `http.method == 'POST'`.
#   - Prefix / suffix / substring: `k8s.name.startsWith('debug-')`,
#     `k8s.resource.endsWith('/exec')`,
#     `http.body.contains('approve_')`.
#   - Regex (for what globs and startsWith can't express):
#     `sql.statement.matches('(?i)\\bsecret\\b')`.
#   - List intersection (sql `tables` / `function` against a
#     deny-list):
#     `sets.intersects(sql.function, ['pg_read_file', ...])`.
#     The `sets` extension is registered on every facet env.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 6. APPROVE CHAINS                                                ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# `approve = [...]` is an ordered list of bare-name stages. Each stage
# names an approver block; the request runs each in turn; any stage
# denying ends the chain.
#
#     approve = [pg-secret-columns-judge]            # one LLM proctor
#     approve = [reply-content-judge, support-ops]   # LLM, then human
#
# LLM proctor blocks (llm_approver) bind a `policy = <name>` directly,
# so the use site stays a bare-name reference. A human stage takes only
# the approver name; the approver block carries channel, timeout, and
# require_approvers.
#
# Defaults block sets `llm_fail_mode` (deny on LLM error / timeout)
# and `human_on_timeout` (deny if Slack approver doesn't reply within
# `human_timeout`).
#
# Use cases this shape covers:
#
#   - LLM-then-human (deno-deploy reply-on-behalf): the content-safety
#     LLM judge runs first, then a human in #agent-support.
#   - LLM-only proctoring (pg-deployng-secret-columns): a column-level
#     read of sensitive tables goes through Claude with a
#     domain-specific prompt.
#   - Human-only (stripe-extra-scrutiny): a curated set of destructive
#     paths gets routed to billing-strict (require_approvers = 2).
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 7. PROFILES                                                      ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# A profile is just an endpoint membership list:
#
#     profile "kaju" { endpoints = [github-kaju, slack-kaju, ...] }
#
# Three observations:
#
#   - Profiles do NOT reference rules. Rules are tied to endpoints, so
#     including an endpoint in a profile transitively includes every
#     rule attached to that endpoint.
#
#   - Sharing is by reference. notion / grafana / ch-o11y-* / k8s-dev-*
#     all appear in multiple profiles; they map to one row each in
#     unclaw, with M:N joins to the listed profiles.
#
#   - Per-user variants are separate endpoints. `github-avocet`,
#     `github-kaju`, `github-mira` all hit api.github.com but each
#     binds a different PAT. The profile names the right one.
#
# v14 has three profiles:
#
#   avocet — full ops coverage (Anthropic dual-cred, Stripe, Orb,
#            console.deno.com, both postgres servers, all k8s
#            clusters, ClickHouse, Notion, Grafana, Slack).
#   kaju   — operational tools (per-user GitHub/Slack, plus
#            tool-specific APIs: Smithery, AMem, Checkly, PostHog,
#            Honeycomb, PagerDuty, support.deno.com).
#   mira   — light profile (her own GitHub/Slack/Telegram/Codex/Gemini
#            plus shared access to divy's Codex OAuth).
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 8. ENDPOINT-LEVEL DESIGN NOTES                                   ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# - Hosts include port when non-default:
#     hosts = ["denoland.grafana.net", "localhost:8443"]
#   No separate `port` field. Default ports are plugin-defined (https
#   → 443, postgres → 5432, clickhouse_https → 443, clickhouse_native
#   → 9440, ...).
#
# - Postgres tunnel: `tunnel = { type = "kubectl-portforward-ssh",
#   cluster, profile, ssh_pod }` describes the kubectl port-forward
#   to an in-cluster ssh-server pod that proxies the RDS connection.
#   Lives on the endpoint because it's per-server, not per-credential.
#
# - Kubernetes mTLS PEMs are referenced by filename:
#     ca_cert = "<<file:k8s-dev-ams-ca.pem>>"
#   The loader inlines the PEM content from a sibling directory at
#   load time. Keeps cert material out of this file.
#
# - EKS auth (k8s-eks-deployng-prod) uses an `aws_eks_credential`,
#   which the kubernetes plugin understands as "fetch a fresh bearer
#   token via aws eks get-token at request time" — cluster, region,
#   and AWS profile name go on the credential.

unknown_host = "passthrough"
llm_fail_mode = "closed"
llm_cache_ttl = 300
human_timeout = 600
human_on_timeout = "deny"

# ── Approvers ────────────────────────────────────────
#
# Two LLM tiers:
#   fast            — Haiku, default proctor for cheap/repetitive checks
#                     (postgres column-level reads, k8s exec content)
#   content-safety  — Sonnet, used when the prompt requires reasoning
#                     about user-visible content (Slack reply shape,
#                     deno-deploy reply-on-behalf)
#
# Human approvers are scoped per concern: support-ops, console-dba,
# scheduler-ops, billing, billing-strict, observability, notion-archive.
# `billing-strict` requires two approvers (`require_approvers = 2`)
# for the highest-blast-radius Stripe operations.

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
#
# A `policy` block holds prompt text used by an LLM proctor stage.
# Pulled out as named blocks so the same prompt can be reused across
# rules, and so the prompt is auditable as a first-class artifact
# (rather than hidden inside a rule body). An llm_approver block binds
# a `policy = <name>` reference to one of these.

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
#
# Every credential is a typed handle. The actual secret material is
# stored separately in unclaw and looked up at inject time by name.
# Credential blocks here only carry parameters that the plugin needs
# in order to know HOW to inject (cookie name, postgres user,
# stripe idempotency-key behaviour, EKS cluster info, header name
# overrides, ...). They never hold the secret value itself.

# avocet's anthropic — both an API key AND an OAuth subscription. The
# agent picks via placeholder; api-key is preferred for raw-API
# usage, subscription is preferred for higher rate limits / cheaper
# tokens during normal operation.
credential "anthropic_manual_key" "anthropic-avocet-key" {
}
credential "anthropic_oauth_subscription" "anthropic-avocet-sub" {
}

# Per-user GitHub PATs. Same hosts (api.github.com, github.com) but
# different secret per user — three endpoints, three credentials.
credential "bearer_token" "github-avocet-pat" {}
credential "bearer_token" "github-kaju-pat"   {}
credential "bearer_token" "github-mira-pat"   {}

# Slack tokens. The slack_tokens credential type bundles bot+app
# tokens for a single workspace; Slack's plugin injects whichever is
# appropriate for the destination API. One credential per workspace.
credential "slack_tokens" "slack-avocet-cred" {}
credential "slack_tokens" "slack-kaju-cred"   {}
credential "slack_tokens" "slack-mira-cred"   {}

# Telegram bot tokens.
credential "telegram_bot_token" "telegram-divy-cred" {}
credential "telegram_bot_token" "telegram-mira-cred" {}

# Gemini (mira only).
credential "gemini_api_key" "gemini-mira-cred" {}

# OpenAI Codex OAuth — divy's is shared between kaju and mira.
credential "openai_codex_oauth" "openai-codex-divy-cred" {}
credential "openai_codex_oauth" "openai-codex-mira-cred" {}

# avocet-only.
# `idempotency_key = true` on stripe-live-key tells the apikey plugin
# to also stamp an Idempotency-Key header on writes, so the same
# request retried by the agent doesn't cause double-charge.
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

# Shared (referenced by multiple profiles).
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

# kaju's per-tool API tokens. These illustrate the variety of HTTP
# auth shapes the bearer/header_token credentials cover:
#   - bearer_token        → Authorization: Bearer <secret>
#   - header_token        → custom header name + optional prefix
#                           (honeycomb uses x-honeycomb-team raw;
#                            pagerduty uses authorization: Token token=<secret>)
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
#
# Endpoint blocks hold ONLY connection / credential info — no rules,
# no defaults. Rules attach upward via top-level `rule {}` blocks.

# Multi-account anthropic (avocet only). Two credential types
# coexist behind a placeholder dispatch; the agent picks api-key vs
# oauth-subscription per call.
endpoint "https" "anthropic-avocet" {
  hosts = ["api.anthropic.com"]
  credentials = [
    { placeholder = "PH_anthropic_avocet_apikey", credential = anthropic-avocet-key },
    { placeholder = "PH_anthropic_avocet_subscription", credential = anthropic-avocet-sub },
  ]
}

# Per-user GitHub. Same hosts, different credentials → three
# endpoints. Each profile names exactly one of these.
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

# Per-user Slack.
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

# Per-user Telegram / Codex / Gemini.
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

# avocet-only services.
endpoint "https" "deno-deploy" {
  hosts       = ["console.deno.com"]
  credential = deno-deploy-pat
}
endpoint "https" "stripe" {
  hosts       = ["api.stripe.com"]
  credential = stripe-live-key
}
# orb test vs prod: same hosts, two credentials. Placeholder dispatch
# lets the agent pick at request time without changing endpoints.
# Rules below match on `credential = orb-prod-key` to lock prod
# behind approval while letting test go through unchecked.
endpoint "https" "orb" {
  hosts = ["api.withorb.com"]
  credentials = [
    { placeholder = "PH_orb_test", credential = orb-test-key },
    { placeholder = "PH_orb_prod", credential = orb-prod-key },
  ]
}

# Postgres. Network reachability is arranged out-of-band; tunnel
# topology declarations land when the postgres runtime hooks ship.
endpoint "postgres" "pg-deployng" {
  host     = "deployng-prod.cluster-cnmc6k08siv7.us-east-2.rds.amazonaws.com:5432"
  database = "deployng"
  # ro/rw dispatch via placeholder. Ro is the default for reads;
  # rw requires explicit selection AND human approval (see rules).
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

# Shared (multiple profiles).
endpoint "https" "notion" {
  hosts       = ["api.notion.com", "mcp.notion.com"]
  credential = notion-deno
}
endpoint "https" "grafana" {
  hosts       = ["denoland.grafana.net"]
  credential = grafana-token
}
# ClickHouse exposes two protocols on the same upstream cluster.
# Two endpoint rows, distinct names, one shared credential. Rules
# can attach to both via `endpoints = [ch-o11y-https, ch-o11y-native]`.
endpoint "clickhouse_https" "ch-o11y-https" {
  hosts       = ["clickhouse-o11y.tail9a48e.ts.net", "ch-o11y.infra.deno-gcp.net"]
  credential = ch-o11y
}
endpoint "clickhouse_native" "ch-o11y-native" {
  hosts       = ["clickhouse-o11y.tail9a48e.ts.net"]
  credential = ch-o11y
}
# Self-hosted k8s clusters use mTLS. The CA cert is referenced by
# filename and inlined at load time.
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

# kaju's per-tool endpoints. One endpoint per upstream API; minimal
# rule coverage (most are passthrough with credential injection only).
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
#
# Each section below covers one upstream service or service family.
# The pattern is consistent:
#
#   1. Allow reads (GET / SELECT) outright.
#   2. Allow specific safe write paths (annotations, snapshots,
#      ephemeral keys, search) outright.
#   3. Override-priority rules for the most dangerous mutations
#      (extra-scrutiny billing endpoints, k8s secret reads, k8s
#      port-forward outside debug-* pods).
#   4. Default-priority rules for normal writes → human approval.
#   5. Negative-priority catch-all denies anything that fell through.
#
# Only deno-deploy, stripe, and most postgres / k8s endpoints have an
# explicit catch-all. Endpoints with simple shapes (notion, grafana,
# slack-avocet, github-*) leave fall-through semantics to unclaw's
# default behaviour.

# ── Slack ───────────────────────────────────────────
#
# Slack rules only target slack-avocet (the only profile with custom
# Slack rules). The single rule guards the support-team's outbound
# email-by-Slack-button flow: messages containing approve_reply_*
# action IDs go through an LLM proctor that verifies the Block Kit
# shape matches what the human reviewer will see.

rule "slack-avocet-approve-reply-shape" {
  endpoint  = slack-avocet
  condition = "http.method == 'POST' && http.path == '/api/chat.postMessage' && http.body.contains('approve_reply_')"
  approve   = [slack-block-kit-shape-judge]
}

# ── Deno Deploy ─────────────────────────────────────
#
# console.deno.com support flow. Reads are free. Two specific support-
# ticket mutations route to the support-ops human approver. The
# reply-on-behalf endpoint sends customer-visible email content, so
# it goes through the content-safety LLM first (catches markdown,
# missing salutation, abusive content) and then support-ops human
# approval. Everything else denies via the catch-all.

rule "deno-deploy-reads" {
  endpoint  = deno-deploy
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
rule "deno-deploy-ticket-mutations" {
  endpoint  = deno-deploy
  condition = "http.method == 'POST' && http.path in ['/api/trpc/admin.supportTickets.markAsSpam', '/api/trpc/admin.supportTickets.updateStatus']"
  approve   = [support-ops]
}
rule "deno-deploy-reply-on-behalf" {
  endpoint  = deno-deploy
  condition = "http.method == 'POST' && http.path == '/api/trpc/admin.supportTickets.replyOnBehalf'"
  approve   = [reply-content-judge, support-ops]
}
rule "deno-deploy-default" {
  endpoint = deno-deploy
  priority = -100
  verdict  = "deny"
  reason   = "console.deno.com mutations require an explicit approval rule"
}

# ── Stripe ──────────────────────────────────────────
#
# Reads free. Ephemeral keys are a read-only-by-design POST (creates
# a short-lived API key with no real side effect; allowed via a
# priority=100 override since it would otherwise hit the
# stripe-other-writes default). DELETEs are blocked outright (Stripe
# uses POST-with-action for deletes; explicit DELETE shouldn't reach
# here). The extra-scrutiny path lists every operation that can move
# real money or invalidate an invoice, and routes those to
# billing-strict (require_approvers = 2). Everything else POST →
# billing single-approver. Catch-all denies the long tail.

rule "stripe-reads" {
  endpoint  = stripe
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
rule "stripe-ephemeral-keys" {
  endpoint  = stripe
  priority  = 100
  condition = "http.method == 'POST' && http.path == '/v1/ephemeral_keys'"
  verdict   = "allow"
}
rule "stripe-no-deletes" {
  endpoint  = stripe
  condition = "http.method == 'DELETE'"
  verdict   = "deny"
  reason    = "Stripe deletes go through the approval flow as POST"
}
rule "stripe-extra-scrutiny" {
  endpoint  = stripe
  priority  = 100
  condition = "http.method == 'POST' && (http.path in ['/v1/refunds', '/v1/subscriptions', '/v1/subscription_items', '/v1/payouts', '/v1/transfers', '/v1/coupons', '/v1/promotion_codes'] || http.path.startsWith('/v1/charges/') && http.path.endsWith('/refund') || http.path.startsWith('/v1/subscriptions/') || http.path.startsWith('/v1/customers/') && http.path.endsWith('/subscriptions') || http.path.startsWith('/v1/invoices/') && (http.path.endsWith('/void') || http.path.endsWith('/finalize')))"
  approve   = [billing-strict]
}
rule "stripe-other-writes" {
  endpoint  = stripe
  condition = "http.method == 'POST'"
  approve   = [billing]
}
rule "stripe-default" {
  endpoint = stripe
  priority = -100
  verdict  = "deny"
}

# ── Orb ─────────────────────────────────────────────
#
# Two credentials behind one endpoint, dispatched via placeholder.
# Test key: anything goes. Prod key: reads free, deletes denied,
# writes go to billing approver. Note the use of `credential = ...`
# in match blocks — the same endpoint, different rules per credential.
# This is the case the v11→v12 placeholder relocation was driven by.

rule "orb-test-allow-all" {
  endpoint   = orb
  credential = orb-test-key
  verdict    = "allow"
}
rule "orb-prod-reads" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "http.method == 'GET'"
  verdict    = "allow"
}
rule "orb-prod-no-deletes" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "http.method == 'DELETE'"
  verdict    = "deny"
  reason     = "Orb deletes go through approval flow as POST"
}
rule "orb-prod-writes" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "http.method in ['POST', 'PUT', 'PATCH']"
  approve    = [billing]
}

# ── Notion ──────────────────────────────────────────
#
# Read-heavy by design. The archive override (priority 100) catches
# PATCH /v1/pages/*/blocks/*/databases/* with `{archived: true}` body
# — Notion's "delete" semantic — and routes it to notion-archive
# alongside actual DELETE. Everything else (creates, edits) is allowed
# outright since Notion content is low-blast-radius.

rule "notion-reads" {
  endpoint  = notion
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "notion-search" {
  endpoint  = notion
  condition = "http.method == 'POST' && http.path == '/v1/search'"
  verdict   = "allow"
}
rule "notion-archive-route" {
  endpoint  = notion
  priority  = 100
  condition = "http.method == 'PATCH' && (http.path.startsWith('/v1/pages/') || http.path.startsWith('/v1/blocks/') || http.path.startsWith('/v1/databases/')) && http.body_json.archived == true"
  approve   = [notion-archive]
}
rule "notion-deletes" {
  endpoint  = notion
  condition = "http.method == 'DELETE'"
  approve   = [notion-archive]
}
rule "notion-create-update" {
  endpoint  = notion
  condition = "http.method in ['POST', 'PATCH']"
  verdict   = "allow"
}

# ── Grafana ─────────────────────────────────────────
#
# Reads + low-impact writes (annotations, snapshots) are allowed.
# Destructive deletes of dashboards, datasources, folders, and alert
# rules are denied — those go through a PR. Updates to those same
# resources go through the observability approver.

rule "grafana-reads" {
  endpoint  = grafana
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "grafana-annotations-snapshots" {
  endpoint  = grafana
  condition = "http.method == 'POST' && http.path in ['/api/annotations', '/api/snapshots']"
  verdict   = "allow"
}
rule "grafana-no-destructive-deletes" {
  endpoint  = grafana
  condition = "http.method == 'DELETE' && (http.path.startsWith('/api/dashboards/') || http.path.startsWith('/api/datasources/') || http.path.startsWith('/api/folders/') || http.path.startsWith('/api/alert-rules/'))"
  verdict   = "deny"
  reason    = "Destructive deletes go through a PR, not the agent"
}
rule "grafana-dashboard-writes" {
  endpoint  = grafana
  condition = "http.method in ['POST', 'PUT', 'PATCH'] && (http.path.startsWith('/api/dashboards/') || http.path.startsWith('/api/datasources/') || http.path.startsWith('/api/folders/') || http.path.startsWith('/api/alert-rules/'))"
  approve   = [observability]
}

# ── ClickHouse (https + native, same rules apply) ───
#
# ClickHouse access is strictly read-only. Both rules attach to BOTH
# protocol endpoints via `endpoints = [ch-o11y-https, ch-o11y-native]`
# — one rule, two targets, no duplication.

rule "clickhouse-reads" {
  endpoints = [ch-o11y-https, ch-o11y-native]
  condition = "sql.verb in ['select', 'show', 'describe', 'explain', 'use']"
  verdict   = "allow"
}
rule "clickhouse-default" {
  endpoints = [ch-o11y-https, ch-o11y-native]
  priority  = -100
  verdict   = "deny"
  reason    = "ClickHouse access is read-only"
}

# ── Postgres — banned across all postgres endpoints ─
#
# These rules apply to BOTH pg-deployng and pg-scheduler — anything
# the agent should never be able to do regardless of which database.
# DDL, dangerous functions, COPY ... PROGRAM, and the migrations
# table are all blocked uniformly. Per-database rules follow.

rule "pg-banned-verbs" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "sql.verb in ['drop', 'truncate', 'alter', 'grant', 'revoke', 'vacuum', 'create', 'comment', 'do']"
  verdict   = "deny"
  reason    = "Schema changes / destructive DDL not permitted; use a migration PR"
}
rule "pg-banned-functions" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "sets.intersects(sql.function, ['pg_terminate_backend', 'pg_cancel_backend', 'pg_read_file', 'pg_read_binary_file', 'lo_get']) || sql.function.exists(f, f.startsWith('dblink_'))"
  verdict   = "deny"
  reason    = "Disallowed function for agent access"
}
rule "pg-banned-copy-from" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "sql.statement.matches('(?is)copy.*from program')"
  verdict   = "deny"
  reason    = "COPY ... FROM PROGRAM is disallowed"
}
rule "pg-banned-copy-to" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "sql.statement.matches('(?is)copy.*to program')"
  verdict   = "deny"
  reason    = "COPY ... TO PROGRAM is disallowed"
}
rule "pg-no-migrations" {
  endpoints = [pg-deployng, pg-scheduler]
  condition = "'kysely_migration' in sql.tables"
  verdict   = "deny"
  reason    = "Migrations table is owned by the deploy pipeline"
}

# ── Postgres — pg-deployng-specific account rules ───
#
# pg-deployng has ro/rw credentials. The ro account is read-only by
# database grants too, but we deny writes here for fast feedback (no
# need to round-trip to pg). Reads of sensitive tables (env vars,
# tokens, certs) go through an LLM proctor that checks whether secret
# columns are actually being projected — priority=100 so it overrides
# pg-deployng-reads. Rw writes go to console-dba.

rule "pg-deployng-ro-no-writes" {
  endpoint   = pg-deployng
  credential = pg-deployng-ro
  condition  = "sql.verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  verdict    = "deny"
  reason     = "ro account is read-only — use the rw placeholder if you need to write"
}
rule "pg-deployng-secret-columns" {
  endpoint  = pg-deployng
  priority  = 100
  condition = "sql.verb == 'select' && sets.intersects(sql.tables, ['github_identities', 'tokens', 'email_confirmations', 'authorizations', 'domain_certificates', 'database_instances', 'env_vars'])"
  approve   = [pg-secret-columns-judge]
}
rule "pg-deployng-rw-writes" {
  endpoint   = pg-deployng
  credential = pg-deployng-rw
  condition  = "sql.verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  approve    = [console-dba]
}
rule "pg-deployng-reads" {
  endpoint  = pg-deployng
  condition = "sql.verb in ['select', 'show', 'explain']"
  verdict   = "allow"
}
rule "pg-deployng-default" {
  endpoint = pg-deployng
  priority = -100
  verdict  = "deny"
}

# ── Postgres — pg-scheduler-specific rules ──────────
#
# pg-scheduler is single-credential. Reads with secret-suggestive
# column names go through an LLM proctor (overrides pg-scheduler-
# reads via priority=100). Writes go to scheduler-ops.

rule "pg-scheduler-secret-named-defense" {
  endpoint  = pg-scheduler
  priority  = 100
  condition = "sql.verb == 'select' && sql.statement.matches('(?i)\\\\b(secret|password|token|api_key|private_key|access_key|signing_secret)\\\\b')"
  approve   = [pg-secret-named-defense-judge]
}
rule "pg-scheduler-writes" {
  endpoint  = pg-scheduler
  condition = "sql.verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  approve   = [scheduler-ops]
}
rule "pg-scheduler-reads" {
  endpoint  = pg-scheduler
  condition = "sql.verb in ['select', 'show', 'explain']"
  verdict   = "allow"
}
rule "pg-scheduler-default" {
  endpoint = pg-scheduler
  priority = -100
  verdict  = "deny"
}

# ── Kubernetes — base rules across all clusters ─────
#
# Applied uniformly to all three clusters (k8s-dev-ams, k8s-dev-ord,
# k8s-eks-deployng-prod). The three high-priority rules at 1000
# (no-secrets, no-interactive, no-portforward-non-debug) are
# non-negotiable safety blocks: secret values can't leave via the
# agent, interactive shells can't be policy-evaluated, and port-
# forward is restricted to debug-* pods. The exec-content-check at
# 500 LLM-evaluates pods/exec command contents.
#
# Mutations are blocked except on debug-* pods (the standard pattern
# for one-off debugging). exec/attach/portforward verbs are allowed
# (the safety blocks above already restrict them appropriately).

rule "k8s-no-secrets" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 1000
  condition = "k8s.resource == 'secrets'"
  verdict   = "deny"
  reason    = "Secret values must not leave the cluster via the agent"
}
rule "k8s-no-interactive" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 1000
  condition = "k8s.resource in ['pods/exec', 'pods/attach'] && k8s.params.stdin == 'true'"
  verdict   = "deny"
  reason    = "Interactive shells can't be evaluated by the rules engine"
}
rule "k8s-no-disruptive" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "k8s.verb in ['drain', 'cordon', 'evict']"
  verdict   = "deny"
  reason    = "Cluster-disruptive operations are not allowed"
}
rule "k8s-no-portforward-non-debug" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 1000
  condition = "k8s.resource == 'pods/portforward' && !k8s.name.startsWith('debug-')"
  verdict   = "deny"
  reason    = "Port-forward only allowed to debug-* pods"
}
rule "k8s-no-mutations" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "k8s.verb in ['create', 'update', 'patch', 'delete'] && !k8s.name.startsWith('debug-') && !k8s.resource.endsWith('/exec') && !k8s.resource.endsWith('/attach') && !k8s.resource.endsWith('/portforward')"
  verdict   = "deny"
  reason    = "Only debug-* pods may be created / modified / deleted"
}
rule "k8s-exec-content-check" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  priority  = 500
  condition = "k8s.resource == 'pods/exec'"
  approve   = [k8s-exec-content-judge]
}
rule "k8s-allow-meta" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "k8s.verb == 'meta'"
  verdict   = "allow"
}
rule "k8s-reads" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "k8s.verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}
rule "k8s-debug-pods" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "k8s.verb in ['create', 'delete'] && k8s.resource == 'pods' && k8s.name.startsWith('debug-')"
  verdict   = "allow"
}
rule "k8s-exec-attach" {
  endpoints = [k8s-dev-ams, k8s-dev-ord, k8s-eks-deployng-prod]
  condition = "k8s.verb in ['create', 'get'] && k8s.resource in ['pods/exec', 'pods/attach', 'pods/portforward']"
  verdict   = "allow"
}

# ── Kubernetes — EKS-specific extras ────────────────
#
# Production-only blocks. Writes to runtime namespaces (console,
# kube-system, cert-manager, external-secrets, argocd, flux*) are
# denied even for debug-* pods — those namespaces are managed by
# GitOps. Some legacy configmaps in the console namespace still hold
# cleartext secrets (named *-secrets or env-*); reads of those are
# blocked even though configmaps reads are otherwise allowed.

rule "k8s-eks-no-runtime-writes" {
  endpoint  = k8s-eks-deployng-prod
  priority  = 1000
  condition = "k8s.verb in ['create', 'update', 'patch', 'delete'] && (k8s.namespace in ['console', 'kube-system', 'cert-manager', 'external-secrets', 'argocd'] || k8s.namespace.startsWith('flux'))"
  verdict   = "deny"
  reason    = "Writes to runtime namespaces would impact production"
}
rule "k8s-eks-no-legacy-secret-configmaps" {
  endpoint  = k8s-eks-deployng-prod
  priority  = 1000
  condition = "k8s.verb in ['get', 'list'] && k8s.resource == 'configmaps' && k8s.namespace == 'console' && (k8s.name.endsWith('-secrets') || k8s.name.startsWith('env-'))"
  verdict   = "deny"
  reason    = "Some legacy configmaps still carry cleartext secrets"
}

# ── Kubernetes catch-alls (per cluster) ─────────────

rule "k8s-dev-ams-default" {
  endpoint = k8s-dev-ams
  priority = -100
  verdict  = "deny"
}
rule "k8s-dev-ord-default" {
  endpoint = k8s-dev-ord
  priority = -100
  verdict  = "deny"
}
rule "k8s-eks-default" {
  endpoint = k8s-eks-deployng-prod
  priority = -100
  verdict  = "deny"
}

# ── Profiles ────────────────────────────────────────
#
# Endpoint membership lists. A profile gets exactly the endpoints it
# names; rules ride along automatically because they're attached to
# endpoints. Sharing happens by listing the same endpoint name from
# multiple profiles.

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
