# Example policy (v15).
#
# v15 inverts the v14 dependency direction. Today's shape:
#
#     endpoint → (nothing)
#     credential → endpoint
#     rule → endpoint  (+ optional credential predicate)
#     approver → credential
#     profile → credential
#
# An endpoint is a pure network target — hosts + protocol-family
# connection params, no credential refs, no dispatch table. The
# credential, not the endpoint, owns the binding between "secret
# material" and "where it gets injected." Profiles enumerate the
# secrets a user is allowed to wield; endpoint membership rides along
# transitively (profile → credentials → endpoints).
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 1. WHAT THIS FILE IS                                             ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# The gateway sits between an agent and the upstream services it talks
# to (GitHub, Slack, Postgres, Kubernetes, Stripe, ...). For every
# request the agent issues, the gateway does two things:
#
#   1. Inject the right credential into the request (replace a
#      placeholder header / cookie / SQL password with a real secret).
#   2. Apply policy rules: allow, deny with a reason, or route through
#      one or more approvers (LLM proctor and / or human-in-Slack).
#
# This file describes both jobs in one document. It is lowered to flat
# tables in the gateway's SQLite store at load time; nothing in this
# file is interpreted at request time, only the lowered rows are.
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
#                                         (Claude proctor, carries its
#                                         own inline `policy` text) or
#                                         human_approver (Slack channel)
#
#   endpoint     "<type>" "<name>" {}     a typed upstream binding —
#                                         hosts + connection params only.
#                                         Types: http, postgres,
#                                         kubernetes, clickhouse_https,
#                                         clickhouse_native.
#
#   credential   "<type>" "<name>" {}     a typed handle to a secret
#                                         (bearer_token, mtls_credential,
#                                         postgres_credential, ...).
#                                         Names the endpoint(s) it
#                                         authenticates against. The
#                                         actual secret value lives
#                                         in the gateway's credential
#                                         store, keyed by name.
#
#   rule         "<name>" {}              one policy decision targeting
#                                         one or more endpoints. The
#                                         rule's family is inferred from
#                                         its endpoint set and pins the
#                                         CEL variable bound in the
#                                         `condition` expression.
#
#   profile      "<name>" {}              credential membership list — a
#                                         user / agent identity dispatches
#                                         against the credentials in its
#                                         profile, and (transitively) the
#                                         endpoints those credentials bind.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 3. NAMES AND REFERENCES                                          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Per-kind namespace. Names must be unique within a kind; the same
# string may name one endpoint and one credential (different kinds)
# without collision, because every reference syntactically carries the
# kind via its type label.
#
# References are typed traversals — `<type>.<name>` for two-label
# kinds, `<kind>.<name>` for one-label kinds:
#
#     endpoint    = http.anthropic-ops
#     credentials = [bearer_token.github-ops]
#     approve     = [llm_approver.fast]
#
# The leading label is required: the loader resolves `http.foo` as
# the endpoint of type `http` named `foo`. There is no bare-name
# resolution and no `credential.bearer_token...` triple-segment form.
#
# Note: ClickHouse exposes two protocols (HTTPS API + native binary)
# from the same upstream cluster, so two endpoints share the upstream:
# `ch-o11y-https` and `ch-o11y-native`. One credential (`ch-o11y`)
# binds both via
# `endpoints = [clickhouse_https.ch-o11y-https, clickhouse_native.ch-o11y-native]`.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 4. CREDENTIAL → ENDPOINT BINDING                                 ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Each credential declares which endpoint(s) it authenticates against.
# Two binding shapes:
#
#   (a) Singular:
#
#         credential "bearer_token" "grafana" {
#           endpoint = http.grafana
#         }
#
#       The credential authenticates exactly one endpoint. This is the
#       common case.
#
#   (b) Singleton-or-list, for one credential reused at multiple
#       protocol endpoints of the same upstream:
#
#         credential "clickhouse_credential" "ch-o11y" {
#           endpoints = [clickhouse_https.ch-o11y-https, clickhouse_native.ch-o11y-native]
#           user      = "ops"
#         }
#
#       The same secret authenticates at all listed endpoints. Used
#       when one upstream exposes the same auth material over multiple
#       protocol surfaces (clickhouse_https + clickhouse_native).
#
# Multi-credential dispatch (placeholder, on the profile). When a
# profile actively wields more than one credential at the same
# endpoint, the credentials list mixes direct traversal entries with
# inline `{ placeholder = "PH_...", credential = <type>.<name> }`
# objects that name the dispatch discriminator the agent sends for each:
#
#     profile "ops" {
#       credentials = [
#         { placeholder = "PH_orb_test", credential = bearer_token.orb-test },
#         { placeholder = "PH_orb_prod", credential = bearer_token.orb-prod },
#         ...
#       ]
#     }
#
# At inject time the gateway scans the request for one of the
# placeholders and substitutes the matching credential's real secret.
# A direct credential traversal in the same profile is the
# no-placeholder fallback — at most one per (profile, endpoint), used
# when no agent placeholder matches. The exact "no-placeholder" semantic is
# plugin-defined: HTTPS overwrites Authorization regardless of what
# the agent sent; postgres swaps the agent's password for the real
# one.
#
# Why placeholders live on the profile, not on the credential:
#
#   - A placeholder is only needed when a profile uses more than one
#     credential at the same endpoint. Per-user-fanout endpoints
#     (github, slack, telegram, openai-codex) globally have multiple
#     credentials, but each profile typically wields just one — so
#     declaring placeholders on the credential side adds noise that no
#     profile actually consults. Profile-scoped placeholders only
#     appear where ambiguity actually exists.
#   - Credentials become pure secret handles + endpoint binding,
#     symmetrical with the way endpoints are pure network targets.
#   - Adding the same credential to a second profile that needs a
#     different discriminator (rare, but legal) is one map entry, not
#     a schema fight.
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
#   - an optional `credential = <type>.<name>` reference (request
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
#   - The data shape matches what the gateway stores (a flat
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
#   http endpoints   → `http` variable
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
#     Example: `support-console-default` (priority -100) denies
#     everything not matched by an earlier explicit rule.
#
# v15 distribution: 11 rules with positive priority (overrides),
# 8 with negative priority (catch-alls), 35 at default 0.
#
# Disabled rules. `disabled = true` keeps a rule in source for audit
# / rollback without removing it. Lowers to `enabled = 0`.
#
# Per-family CEL variables. Each family exposes one struct-typed
# top-level variable; fields are accessed with dot notation.
#
#   http  → http.method, http.path, http.query, http.headers,
#           http.body, http.body_json
#   sql   → sql.verb, sql.tables, sql.functions, sql.statement
#   k8s   → k8s.verb, k8s.resource, k8s.namespace, k8s.name,
#           k8s.params
#
# `verb` (sql, k8s) and `method` (http) are unary strings. `tables`
# and `functions` (sql) are list[string]; `query` and `headers`
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
#   - List intersection (sql `tables` / `functions` against a
#     deny-list):
#     `sets.intersects(sql.functions, ['pg_read_file', ...])`.
#     The `sets` extension is registered on every facet env.
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 6. APPROVE CHAINS                                                ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# `approve = [...]` is an ordered list of approver traversals. Each
# stage names an approver block; the request runs each in turn; any
# stage denying ends the chain.
#
#     approve = [llm_approver.pg-secret-columns-judge]            # one LLM proctor
#     approve = [llm_approver.reply-content-judge, human_approver.support-ops]   # LLM, then human
#
# LLM proctor blocks (llm_approver) carry their `policy` text inline
# as a heredoc string, so the use site stays a single approver
# traversal. A human stage takes only the approver traversal; the
# approver block carries channel, timeout, and require_approvers.
#
# Defaults block sets `llm_fail_mode` (deny on LLM error / timeout)
# and `human_on_timeout` (deny if Slack approver doesn't reply within
# `human_timeout`).
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 7. PROFILES                                                      ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# A profile is a credential membership list:
#
#     profile "alice" { credentials = [bearer_token.github-alice, slack_tokens.slack-alice, ...] }
#
# Three observations:
#
#   - Profiles do NOT reference endpoints directly. Endpoint membership
#     is the transitive closure profile → credentials → endpoints.
#     Rules are tied to endpoints, so including a credential in a
#     profile transitively includes every endpoint that credential
#     binds and every rule attached to it.
#
#   - Sharing is by reference. notion-corp / grafana / ch-o11y /
#     k8s-dev-{iad,sfo}-mtls all appear in multiple profiles; they map
#     to one credential row each, with M:N joins to the listed profiles.
#
#   - Multi-credential endpoints (anthropic-ops, orb, pg-corp) list
#     BOTH credentials in the profile that wields them, wrapped in
#     `{ placeholder = "PH_...", credential = name }` entries that
#     disambiguate the wire-time dispatch. Per-user-fanout endpoints
#     (github, slack, telegram, openai-codex) are also globally
#     multi-credential, but each profile typically wields just one
#     credential per endpoint and needs no placeholders. The one
#     exception is bob's openai-codex — bob wields both his and
#     carol's credentials, so his profile carries inline placeholders
#     on both entries.
#
# v15 has three profiles:
#
#   ops    — full ops coverage (anthropic dual-cred, stripe, orb dual,
#            support console, both postgres servers (pg-corp dual),
#            all k8s clusters, ClickHouse, Notion, Grafana, Slack).
#   alice  — operational tools (per-user GitHub/Slack, plus
#            tool-specific APIs: Smithery, AMem, Checkly, PostHog,
#            Honeycomb, PagerDuty, customer support helpdesk).
#   bob    — light profile (his own GitHub/Slack/Telegram/Codex/Gemini
#            plus shared access to carol's Codex OAuth).
#
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║ 8. ENDPOINT-LEVEL DESIGN NOTES                                   ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# - Hosts include port when non-default:
#     hosts = ["grafana.example.com", "localhost:8443"]
#   No separate `port` field. Default ports are plugin-defined (http
#   → 443, postgres → 5432, clickhouse_https → 443, clickhouse_native
#   → 9440, ...).
#
# - Postgres tunnel: `tunnel = { type = "kubectl-portforward-ssh",
#   cluster, profile, ssh_pod }` describes the kubectl port-forward
#   to an in-cluster ssh-server pod that proxies the RDS connection.
#   Lives on the endpoint because it's per-server, not per-credential.
#
# - Kubernetes mTLS PEMs are referenced by filename:
#     ca_cert = "<<file:k8s-dev-iad-ca.pem>>"
#   The loader inlines the PEM content from a sibling directory at
#   load time. Keeps cert material out of this file.
#
# - EKS auth (k8s-eks-corp-prod) uses an `aws_credential` whose
#   `endpoint = k8s-eks-corp-prod` binds it to that cluster. The
#   gateway presigns an STS GetCallerIdentity URL at request time and
#   stamps the `k8s-aws-v1.<…>` bearer; cluster name and region live
#   on the endpoint.

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

defaults {
  unknown_host     = "passthrough"
  llm_fail_mode    = "closed"
  llm_cache_ttl    = 300
  human_timeout    = 600
  human_on_timeout = "deny"
}

# ── Approvers ────────────────────────────────────────
#
# Two LLM tiers:
#   fast            — Haiku, default proctor for cheap/repetitive checks
#                     (postgres column-level reads, k8s exec content)
#   content-safety  — Sonnet, used when the prompt requires reasoning
#                     about user-visible content (Slack reply shape,
#                     support-console reply-on-behalf)
#
# Human approvers are scoped per concern: support-ops, console-dba,
# scheduler-ops, billing, billing-strict, observability, notion-archive.
# `billing-strict` requires two approvers (`require_approvers = 2`)
# for the highest-blast-radius Stripe operations.
#
# Approvers reference `credential = anthropic_oauth_subscription.anthropic-ops`
# — that traversal resolves to the credential below; the credential
# itself binds the anthropic-ops endpoint, so the approver's outbound
# calls use the same injection path the agent uses.

approver "llm_approver" "slack-block-kit-shape-judge" {
  model      = "claude-sonnet-4-20250514"
  credential = anthropic_oauth_subscription.anthropic-ops
  policy     = <<-EOT
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
approver "llm_approver" "reply-content-judge" {
  model      = "claude-sonnet-4-20250514"
  credential = anthropic_oauth_subscription.anthropic-ops
  policy     = <<-EOT
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
approver "llm_approver" "pg-secret-columns-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic_oauth_subscription.anthropic-ops
  policy     = <<-EOT
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
approver "llm_approver" "pg-secret-named-defense-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic_oauth_subscription.anthropic-ops
  policy     = <<-EOT
    Decide whether this SELECT actually returns secret data — i.e.
    it projects or aggregates a column whose name suggests a secret.
    Approve if the secret-named identifier appears only as a string
    literal or in a non-projected predicate.
  EOT
}
approver "llm_approver" "k8s-exec-content-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic_oauth_subscription.anthropic-ops
  policy     = <<-EOT
    Inspect the kubectl exec command (each ?command= argv element).
    Deny if it dumps env vars (env, printenv, set, export, cat
    /proc/*/environ). Deny if it reads sensitive host-mount files
    (kubelet pod tokens, certs, private keys, kubeconfig,
    /etc/shadow, containerd/CRI sockets). Allow ls, ps, df, ip, ss,
    mount, dmesg, top, and apt-get install for debugging.
  EOT
}

approver "human_approver" "support-ops" {
  channel = "#support"
  timeout = 86400
}
approver "human_approver" "console-dba"    { channel = "#db-approvals" }
approver "human_approver" "scheduler-ops"  { channel = "#db-approvals" }
approver "human_approver" "billing"        { channel = "#billing-approvals" }
approver "human_approver" "billing-strict" {
  channel           = "#billing-approvals"
  require_approvers = 2
}
approver "human_approver" "observability"  { channel = "#observability" }
approver "human_approver" "notion-archive" { channel = "#notion-approvals" }

# ── Endpoints (bare network targets) ────────────────
#
# No `credential` / `credentials` fields. Endpoints only carry
# connection parameters — credential binding lives on the credential
# blocks below.

endpoint "http" "anthropic-ops" { hosts = ["api.anthropic.com"] }

endpoint "http" "github"   { hosts = ["api.github.com", "github.com"] }
endpoint "http" "slack"    { hosts = ["slack.com", "www.slack.com", "api.slack.com"] }
endpoint "http" "telegram" { hosts = ["api.telegram.org"] }
endpoint "http" "gemini"   { hosts = ["generativelanguage.googleapis.com"] }

endpoint "http" "openai-codex" { hosts = ["chatgpt.com", "auth.openai.com"] }

endpoint "http" "support-console" { hosts = ["admin.example.com"] }
endpoint "http" "stripe"          { hosts = ["api.stripe.com"] }
endpoint "http" "orb"             { hosts = ["api.withorb.com"] }

endpoint "postgres" "pg-corp" {
  host = "corp-prod.cluster.example:5432"
}
endpoint "postgres" "pg-scheduler" {
  host = "scheduler-prod.cluster.example:5432"
}

endpoint "kubernetes" "k8s-eks-corp-prod" {
  hosts        = ["*.gr7.us-east-2.eks.amazonaws.com"]
  description  = "arn:aws:eks:us-east-2:123456789012:cluster/corp-prod"
  cluster_name = "corp-prod"
  region       = "us-east-2"
}

endpoint "http" "notion"  { hosts = ["api.notion.com", "mcp.notion.com"] }
endpoint "http" "grafana" { hosts = ["grafana.example.com"] }

# Both ClickHouse endpoints are bare here; the shared credential
# below references both via the singleton-or-list `endpoints` form.
endpoint "clickhouse_https"  "ch-o11y-https"  { hosts = ["clickhouse-o11y.example", "ch-o11y.internal.example"] }
endpoint "clickhouse_native" "ch-o11y-native" { hosts = ["clickhouse-o11y.example"] }

# Self-hosted k8s clusters use mTLS. The CA cert is referenced by
# filename and inlined at load time.
endpoint "kubernetes" "k8s-dev-iad" {
  server      = "198.51.100.10"
  ca_cert     = "<<file:k8s-dev-iad-ca.pem>>"
  description = "admin@dev-iad.example"
}
endpoint "kubernetes" "k8s-dev-sfo" {
  server      = "198.51.100.20"
  ca_cert     = "<<file:k8s-dev-sfo-ca.pem>>"
  description = "admin@dev-sfo.example"
}

# alice's per-tool endpoints.
endpoint "http" "smithery"  { hosts = ["smithery.ai"] }
endpoint "http" "amem"      { hosts = ["api.amem.ai"] }
endpoint "http" "checkly"   { hosts = ["api.checklyhq.com"] }
endpoint "http" "posthog"   { hosts = ["us.i.posthog.com", "us.posthog.com"] }
endpoint "http" "honeycomb" { hosts = ["api.honeycomb.io"] }
endpoint "http" "pagerduty" { hosts = ["api.pagerduty.com"] }
endpoint "http" "helpdesk"  { hosts = ["helpdesk.example.com"] }

# ── Credentials (each names its endpoint) ───────────
#
# Every credential is a typed handle. The actual secret material is
# stored separately in the gateway and looked up at inject time by
# name. Credential blocks here only carry parameters that the plugin
# needs in order to know HOW to inject (cookie name, postgres user,
# stripe idempotency-key behaviour, header name overrides, ...). They
# never hold the secret value itself.
#
# Multi-credential endpoints (anthropic-ops, orb, pg-corp) appear as
# N credentials each pointing at the shared endpoint. The dispatch
# discriminator lives on the profile that wields them — see the
# inline `{ placeholder = "PH_...", credential = ... }` entries in
# profile "ops" below. The shared ch-o11y credential uses the
# singleton-or-list `endpoints` form (one credential, two endpoints).

# ops' anthropic — both an API key AND an OAuth subscription. The
# dispatch placeholder lives on the profile (inline `{ placeholder =
# ..., credential = ... }` entries in profile "ops"), because only
# profiles that wield BOTH credentials need to disambiguate.
credential "anthropic_manual_key"         "anthropic-ops-key" { endpoint = http.anthropic-ops }
credential "anthropic_oauth_subscription" "anthropic-ops" { endpoint = http.anthropic-ops }

# Per-user GitHub PATs. The github endpoint is a bare network target
# shared across users; each user's profile wields exactly one of these,
# so no placeholder is needed in any profile.
credential "bearer_token" "github-ops"   { endpoint = http.github }
credential "bearer_token" "github-alice" { endpoint = http.github }
credential "bearer_token" "github-bob"   { endpoint = http.github }

# Per-user Slack workspaces — shared slack endpoint, each user's
# profile uses one workspace credential.
credential "slack_tokens" "slack-ops"   { endpoint = http.slack }
credential "slack_tokens" "slack-alice" { endpoint = http.slack }
credential "slack_tokens" "slack-bob"   { endpoint = http.slack }

# Per-user Telegram / Codex / Gemini. The openai-codex endpoint is
# the only one any profile binds with more than one credential
# (profile "bob" uses both his and carol's codex), so the
# disambiguation placeholders live in that profile.
credential "telegram_bot_token"  "telegram-carol"     { endpoint = http.telegram }
credential "telegram_bot_token"  "telegram-bob"       { endpoint = http.telegram }
credential "gemini_api_key"      "gemini-bob"         { endpoint = http.gemini }
credential "openai_codex_oauth"  "openai-codex-carol" { endpoint = http.openai-codex }
credential "openai_codex_oauth"  "openai-codex-bob"   { endpoint = http.openai-codex }

# ops-only.
# `idempotency_key = true` tells the bearer_token plugin to also stamp
# an Idempotency-Key header on writes, so the same request retried by
# the agent doesn't cause double-charge.
credential "bearer_token" "stripe-live" {
  endpoint        = http.stripe
  idempotency_key = true
}

# Orb: test + prod. Both wielded by profile "ops" → placeholders
# declared there.
credential "bearer_token" "orb-test" { endpoint = http.orb }
credential "bearer_token" "orb-prod" { endpoint = http.orb }

credential "cookie_token" "support-console" {
  endpoint    = http.support-console
  cookie_name = "session"
}

# pg-corp: ro + rw. Both wielded by profile "ops" → placeholders
# declared there.
credential "postgres_credential" "pg-corp-ro" {
  endpoint = postgres.pg-corp
  user     = "corp_ro"
}
credential "postgres_credential" "pg-corp-rw" {
  endpoint = postgres.pg-corp
  user     = "corp_rw"
}
credential "postgres_credential" "pg-scheduler" {
  endpoint = postgres.pg-scheduler
  user     = "scheduler"
}

credential "notion_oauth" "notion-corp"   { endpoint = http.notion }
credential "bearer_token" "grafana" { endpoint = http.grafana }

# ch-o11y: ONE credential, TWO endpoints. The singleton-or-list
# `endpoints` form preserves the single-credential identity while
# binding both ClickHouse protocol surfaces of the same upstream.
credential "clickhouse_credential" "ch-o11y" {
  endpoints = [clickhouse_https.ch-o11y-https, clickhouse_native.ch-o11y-native]
  user      = "ops"
}

credential "mtls_credential"   "k8s-dev-iad"  { endpoint = kubernetes.k8s-dev-iad }
credential "mtls_credential"   "k8s-dev-sfo"  { endpoint = kubernetes.k8s-dev-sfo }
credential "aws_credential"    "k8s-eks-corp"  { endpoint = kubernetes.k8s-eks-corp-prod }

# alice's per-tool API tokens. These illustrate the variety of HTTP
# auth shapes the bearer/header_token credentials cover:
#   - bearer_token        → Authorization: Bearer <secret>
#   - header_token        → custom header name + optional prefix
#                           (honeycomb uses x-honeycomb-team raw;
#                            pagerduty uses authorization: Token token=<secret>)
credential "bearer_token" "smithery-alice"  { endpoint = http.smithery }
credential "bearer_token" "amem-alice"      { endpoint = http.amem }
credential "bearer_token" "checkly-alice"   { endpoint = http.checkly }
credential "bearer_token" "posthog-alice"   { endpoint = http.posthog }
credential "bearer_token" "helpdesk-alice"  { endpoint = http.helpdesk }
credential "header_token" "honeycomb-alice" {
  endpoint = http.honeycomb
  header   = "x-honeycomb-team"
}
credential "header_token" "pagerduty-alice" {
  endpoint = http.pagerduty
  header   = "authorization"
  prefix   = "Token token="
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

# ── Slack ───────────────────────────────────────────

rule "slack-ops-approve-reply-shape" {
  endpoint   = http.slack
  credential = slack_tokens.slack-ops
  condition  = "http.method == 'POST' && http.path == '/api/chat.postMessage' && http.body.contains('approve_reply_')"
  approve    = [llm_approver.slack-block-kit-shape-judge]
}

# ── Support console ─────────────────────────────────

rule "support-console-reads" {
  endpoint  = http.support-console
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
rule "support-console-ticket-mutations" {
  endpoint  = http.support-console
  condition = "http.method == 'POST' && http.path in ['/api/trpc/admin.supportTickets.markAsSpam', '/api/trpc/admin.supportTickets.updateStatus']"
  approve   = [human_approver.support-ops]
}
rule "support-console-reply-on-behalf" {
  endpoint  = http.support-console
  condition = "http.method == 'POST' && http.path == '/api/trpc/admin.supportTickets.replyOnBehalf'"
  approve   = [llm_approver.reply-content-judge, human_approver.support-ops]
}
rule "support-console-default" {
  endpoint = http.support-console
  priority = -100
  verdict  = "deny"
  reason   = "admin.example.com mutations require an explicit approval rule"
}

# ── Stripe ──────────────────────────────────────────

rule "stripe-reads" {
  endpoint  = http.stripe
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
rule "stripe-ephemeral-keys" {
  endpoint  = http.stripe
  priority  = 100
  condition = "http.method == 'POST' && http.path == '/v1/ephemeral_keys'"
  verdict   = "allow"
}
rule "stripe-no-deletes" {
  endpoint  = http.stripe
  condition = "http.method == 'DELETE'"
  verdict   = "deny"
  reason    = "Stripe deletes go through the approval flow as POST"
}
rule "stripe-extra-scrutiny" {
  endpoint  = http.stripe
  priority  = 100
  condition = "http.method == 'POST' && (http.path in ['/v1/refunds', '/v1/subscriptions', '/v1/subscription_items', '/v1/payouts', '/v1/transfers', '/v1/coupons', '/v1/promotion_codes'] || http.path.startsWith('/v1/charges/') && http.path.endsWith('/refund') || http.path.startsWith('/v1/subscriptions/') || http.path.startsWith('/v1/customers/') && http.path.endsWith('/subscriptions') || http.path.startsWith('/v1/invoices/') && (http.path.endsWith('/void') || http.path.endsWith('/finalize')))"
  approve   = [human_approver.billing-strict]
}
rule "stripe-other-writes" {
  endpoint  = http.stripe
  condition = "http.method == 'POST'"
  approve   = [human_approver.billing]
}
rule "stripe-default" {
  endpoint = http.stripe
  priority = -100
  verdict  = "deny"
}

# ── Orb ─────────────────────────────────────────────
#
# Two credentials behind one endpoint, dispatched via placeholder.
# Rule.credential predicates match on the dispatching credential.

rule "orb-test-allow-all" {
  endpoint   = http.orb
  credential = bearer_token.orb-test
  verdict    = "allow"
}
rule "orb-prod-reads" {
  endpoint   = http.orb
  credential = bearer_token.orb-prod
  condition  = "http.method == 'GET'"
  verdict    = "allow"
}
rule "orb-prod-no-deletes" {
  endpoint   = http.orb
  credential = bearer_token.orb-prod
  condition  = "http.method == 'DELETE'"
  verdict    = "deny"
  reason     = "Orb deletes go through approval flow as POST"
}
rule "orb-prod-writes" {
  endpoint   = http.orb
  credential = bearer_token.orb-prod
  condition  = "http.method in ['POST', 'PUT', 'PATCH']"
  approve    = [human_approver.billing]
}

# ── Notion ──────────────────────────────────────────

rule "notion-reads" {
  endpoint  = http.notion
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "notion-search" {
  endpoint  = http.notion
  condition = "http.method == 'POST' && http.path == '/v1/search'"
  verdict   = "allow"
}
rule "notion-archive-route" {
  endpoint  = http.notion
  priority  = 100
  condition = "http.method == 'PATCH' && (http.path.startsWith('/v1/pages/') || http.path.startsWith('/v1/blocks/') || http.path.startsWith('/v1/databases/')) && http.body_json.archived == true"
  approve   = [human_approver.notion-archive]
}
rule "notion-deletes" {
  endpoint  = http.notion
  condition = "http.method == 'DELETE'"
  approve   = [human_approver.notion-archive]
}
rule "notion-create-update" {
  endpoint  = http.notion
  condition = "http.method in ['POST', 'PATCH']"
  verdict   = "allow"
}

# ── Grafana ─────────────────────────────────────────

rule "grafana-reads" {
  endpoint  = http.grafana
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "grafana-annotations-snapshots" {
  endpoint  = http.grafana
  condition = "http.method == 'POST' && http.path in ['/api/annotations', '/api/snapshots']"
  verdict   = "allow"
}
rule "grafana-no-destructive-deletes" {
  endpoint  = http.grafana
  condition = "http.method == 'DELETE' && (http.path.startsWith('/api/dashboards/') || http.path.startsWith('/api/datasources/') || http.path.startsWith('/api/folders/') || http.path.startsWith('/api/alert-rules/'))"
  verdict   = "deny"
  reason    = "Destructive deletes go through a PR, not the agent"
}
rule "grafana-dashboard-writes" {
  endpoint  = http.grafana
  condition = "http.method in ['POST', 'PUT', 'PATCH'] && (http.path.startsWith('/api/dashboards/') || http.path.startsWith('/api/datasources/') || http.path.startsWith('/api/folders/') || http.path.startsWith('/api/alert-rules/'))"
  approve   = [human_approver.observability]
}

# ── ClickHouse (https + native, same rules apply) ───

rule "clickhouse-reads" {
  endpoints = [clickhouse_https.ch-o11y-https, clickhouse_native.ch-o11y-native]
  condition = "sql.verb in ['select', 'show', 'describe', 'explain', 'use']"
  verdict   = "allow"
}
rule "clickhouse-default" {
  endpoints = [clickhouse_https.ch-o11y-https, clickhouse_native.ch-o11y-native]
  priority  = -100
  verdict   = "deny"
  reason    = "ClickHouse access is read-only"
}

# ── Postgres — banned across all postgres endpoints ─

rule "pg-banned-verbs" {
  endpoints = [postgres.pg-corp, postgres.pg-scheduler]
  condition = "sql.verb in ['drop', 'truncate', 'alter', 'grant', 'revoke', 'vacuum', 'create', 'comment', 'do']"
  verdict   = "deny"
  reason    = "Schema changes / destructive DDL not permitted; use a migration PR"
}
rule "pg-banned-functions" {
  endpoints = [postgres.pg-corp, postgres.pg-scheduler]
  condition = "sets.intersects(sql.functions, ['pg_terminate_backend', 'pg_cancel_backend', 'pg_read_file', 'pg_read_binary_file', 'lo_get']) || sql.functions.exists(f, f.startsWith('dblink_'))"
  verdict   = "deny"
  reason    = "Disallowed function for agent access"
}
rule "pg-banned-copy-from" {
  endpoints = [postgres.pg-corp, postgres.pg-scheduler]
  condition = "sql.statement.matches('(?is)copy.*from program')"
  verdict   = "deny"
  reason    = "COPY ... FROM PROGRAM is disallowed"
}
rule "pg-banned-copy-to" {
  endpoints = [postgres.pg-corp, postgres.pg-scheduler]
  condition = "sql.statement.matches('(?is)copy.*to program')"
  verdict   = "deny"
  reason    = "COPY ... TO PROGRAM is disallowed"
}
rule "pg-no-migrations" {
  endpoints = [postgres.pg-corp, postgres.pg-scheduler]
  condition = "'kysely_migration' in sql.tables"
  verdict   = "deny"
  reason    = "Migrations table is owned by the deploy pipeline"
}

# ── Postgres — pg-corp-specific account rules ───────

rule "pg-corp-ro-no-writes" {
  endpoint   = postgres.pg-corp
  credential = postgres_credential.pg-corp-ro
  condition  = "sql.verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  verdict    = "deny"
  reason     = "ro account is read-only — use the rw placeholder if you need to write"
}
rule "pg-corp-secret-columns" {
  endpoint  = postgres.pg-corp
  priority  = 100
  condition = "sql.verb == 'select' && sets.intersects(sql.tables, ['github_identities', 'tokens', 'email_confirmations', 'authorizations', 'domain_certificates', 'database_instances', 'env_vars'])"
  approve   = [llm_approver.pg-secret-columns-judge]
}
rule "pg-corp-rw-writes" {
  endpoint   = postgres.pg-corp
  credential = postgres_credential.pg-corp-rw
  condition  = "sql.verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  approve    = [human_approver.console-dba]
}
rule "pg-corp-reads" {
  endpoint  = postgres.pg-corp
  condition = "sql.verb in ['select', 'show', 'explain']"
  verdict   = "allow"
}
rule "pg-corp-default" {
  endpoint = postgres.pg-corp
  priority = -100
  verdict  = "deny"
}

# ── Postgres — pg-scheduler-specific rules ──────────

rule "pg-scheduler-secret-named-defense" {
  endpoint  = postgres.pg-scheduler
  priority  = 100
  condition = "sql.verb == 'select' && sql.statement.matches('(?i)\\\\b(secret|password|token|api_key|private_key|access_key|signing_secret)\\\\b')"
  approve   = [llm_approver.pg-secret-named-defense-judge]
}
rule "pg-scheduler-writes" {
  endpoint  = postgres.pg-scheduler
  condition = "sql.verb in ['insert', 'update', 'delete', 'merge', 'notify']"
  approve   = [human_approver.scheduler-ops]
}
rule "pg-scheduler-reads" {
  endpoint  = postgres.pg-scheduler
  condition = "sql.verb in ['select', 'show', 'explain']"
  verdict   = "allow"
}
rule "pg-scheduler-default" {
  endpoint = postgres.pg-scheduler
  priority = -100
  verdict  = "deny"
}

# ── Kubernetes — base rules across all clusters ─────

rule "k8s-no-secrets" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  priority  = 1000
  condition = "k8s.resource == 'secrets'"
  verdict   = "deny"
  reason    = "Secret values must not leave the cluster via the agent"
}
rule "k8s-no-interactive" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  priority  = 1000
  condition = "k8s.resource in ['pods/exec', 'pods/attach'] && k8s.params.stdin == 'true'"
  verdict   = "deny"
  reason    = "Interactive shells can't be evaluated by the rules engine"
}
rule "k8s-no-disruptive" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  condition = "k8s.verb in ['drain', 'cordon', 'evict']"
  verdict   = "deny"
  reason    = "Cluster-disruptive operations are not allowed"
}
rule "k8s-no-portforward-non-debug" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  priority  = 1000
  condition = "k8s.resource == 'pods/portforward' && !k8s.name.startsWith('debug-')"
  verdict   = "deny"
  reason    = "Port-forward only allowed to debug-* pods"
}
rule "k8s-no-mutations" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  condition = "k8s.verb in ['create', 'update', 'patch', 'delete'] && !k8s.name.startsWith('debug-') && !k8s.resource.endsWith('/exec') && !k8s.resource.endsWith('/attach') && !k8s.resource.endsWith('/portforward')"
  verdict   = "deny"
  reason    = "Only debug-* pods may be created / modified / deleted"
}
rule "k8s-exec-content-check" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  priority  = 500
  condition = "k8s.resource == 'pods/exec'"
  approve   = [llm_approver.k8s-exec-content-judge]
}
rule "k8s-allow-meta" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  condition = "k8s.verb == 'meta'"
  verdict   = "allow"
}
rule "k8s-reads" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  condition = "k8s.verb in ['get', 'list', 'watch']"
  verdict   = "allow"
}
rule "k8s-debug-pods" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  condition = "k8s.verb in ['create', 'delete'] && k8s.resource == 'pods' && k8s.name.startsWith('debug-')"
  verdict   = "allow"
}
rule "k8s-exec-attach" {
  endpoints = [kubernetes.k8s-dev-iad, kubernetes.k8s-dev-sfo, kubernetes.k8s-eks-corp-prod]
  condition = "k8s.verb in ['create', 'get'] && k8s.resource in ['pods/exec', 'pods/attach', 'pods/portforward']"
  verdict   = "allow"
}

# ── Kubernetes — EKS-specific extras ────────────────

rule "k8s-eks-no-runtime-writes" {
  endpoint  = kubernetes.k8s-eks-corp-prod
  priority  = 1000
  condition = "k8s.verb in ['create', 'update', 'patch', 'delete'] && (k8s.namespace in ['app', 'kube-system', 'cert-manager', 'external-secrets', 'argocd'] || k8s.namespace.startsWith('flux'))"
  verdict   = "deny"
  reason    = "Writes to runtime namespaces would impact production"
}
rule "k8s-eks-no-legacy-secret-configmaps" {
  endpoint  = kubernetes.k8s-eks-corp-prod
  priority  = 1000
  condition = "k8s.verb in ['get', 'list'] && k8s.resource == 'configmaps' && k8s.namespace == 'app' && (k8s.name.endsWith('-secrets') || k8s.name.startsWith('env-'))"
  verdict   = "deny"
  reason    = "Some legacy configmaps still carry cleartext secrets"
}

# ── Kubernetes catch-alls (per cluster) ─────────────

rule "k8s-dev-iad-default" {
  endpoint = kubernetes.k8s-dev-iad
  priority = -100
  verdict  = "deny"
}
rule "k8s-dev-sfo-default" {
  endpoint = kubernetes.k8s-dev-sfo
  priority = -100
  verdict  = "deny"
}
rule "k8s-eks-default" {
  endpoint = kubernetes.k8s-eks-corp-prod
  priority = -100
  verdict  = "deny"
}

# ── Profiles ────────────────────────────────────────
#
# Credential membership lists. A profile gets exactly the credentials
# it names; endpoint membership is the transitive closure
# profile → credentials → endpoints; rules ride along automatically
# because they're attached to endpoints. Sharing happens by listing
# the same credential name from multiple profiles.

profile "ops" {
  # Bare-name entries are credentials whose endpoint binding is
  # unambiguous in this profile. `{ credential = name, <field> = "..." }`
  # entries name the dispatch discriminator the agent embeds when the
  # profile actively wields more than one credential at the same
  # endpoint. The discriminator field is per-credential-type
  # (placeholder for HTTP-auth, user for postgres, database/user
  # for clickhouse, …) and may equivalently be set on the credential
  # block itself — profile-inline values override block-side ones.
  credentials = [
    # anthropic-ops: BOTH credentials at one endpoint → disambiguated
    # via inline placeholders.
    { placeholder = "PH_anthropic_ops_apikey", credential = anthropic_manual_key.anthropic-ops-key },
    { placeholder = "PH_anthropic_ops_subscription", credential = anthropic_oauth_subscription.anthropic-ops },

    bearer_token.github-ops,
    slack_tokens.slack-ops,
    cookie_token.support-console,
    bearer_token.stripe-live,

    # orb: test + prod at one endpoint.
    { placeholder = "PH_orb_test", credential = bearer_token.orb-test },
    { placeholder = "PH_orb_prod", credential = bearer_token.orb-prod },

    notion_oauth.notion-corp,
    bearer_token.grafana,

    # pg-corp: ro + rw at one endpoint. Disambiguation lives on each
    # credential's `user` block-side field — postgres routes on the
    # StartupMessage user, so the operator never needs a profile-side
    # discriminator here.
    postgres_credential.pg-corp-ro,
    postgres_credential.pg-corp-rw,
    postgres_credential.pg-scheduler,

    mtls_credential.k8s-dev-iad,
    mtls_credential.k8s-dev-sfo,
    aws_credential.k8s-eks-corp,

    # ch-o11y: one credential, two endpoints.
    clickhouse_credential.ch-o11y,
  ]
}

profile "alice" {
  credentials = [
    bearer_token.github-alice,
    slack_tokens.slack-alice,
    telegram_bot_token.telegram-carol,
    openai_codex_oauth.openai-codex-carol,

    # shared with profile.ops:
    notion_oauth.notion-corp,
    bearer_token.grafana,
    clickhouse_credential.ch-o11y,
    mtls_credential.k8s-dev-iad,
    mtls_credential.k8s-dev-sfo,

    # profile.alice's per-tool API access:
    bearer_token.smithery-alice,
    bearer_token.amem-alice,
    bearer_token.checkly-alice,
    bearer_token.posthog-alice,
    header_token.honeycomb-alice,
    header_token.pagerduty-alice,
    bearer_token.helpdesk-alice,
  ]
  # No placeholders: alice's profile binds at most one credential per
  # endpoint, so dispatch is unambiguous without a discriminator.
}

profile "bob" {
  credentials = [
    bearer_token.github-bob,
    slack_tokens.slack-bob,
    telegram_bot_token.telegram-bob,
    gemini_api_key.gemini-bob,

    # bob wields two openai-codex credentials → placeholder dispatch.
    { placeholder = "PH_openai_codex_bob", credential = openai_codex_oauth.openai-codex-bob },

    # shared with alice:
    { placeholder = "PH_openai_codex_carol", credential = openai_codex_oauth.openai-codex-carol },
  ]
}
