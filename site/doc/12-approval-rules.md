# Approval rules

Rules are how an operator decides what happens to a request:
forward it, reject it, or route it through one or more
**approvers** (a human approver who acts from the dashboard or
Slack, an LLM approver that judges against a policy, or both in
sequence) that must each allow before the request is forwarded. Each rule is a
block in `gateway.hcl` that targets one or more
[endpoints](/docs/03a-glossary/#endpoint), describes which requests
it applies to (the `match` block), and declares the outcome
(`verdict = "allow" / "deny"`, or `approve = [...]`).

Three rule types ship today, one per endpoint family. An
`http_rule` lets you keep the agent from using certain HTTP methods
or hitting certain URL paths; a `sql_rule` lets you stop it from
running certain SQL verbs or touching certain tables; a `k8s_rule`
lets you block access to certain Kubernetes resources, verbs, or
namespaces. The next section walks through each in detail.

This page covers the operator's view: how to write a rule, what
each facet does, and how rules behave in different situations.

For the surrounding picture see
[Architecture](/docs/04-architecture/) (request flow, where matching
fits — including how endpoints claim requests) and
[Gateway](/docs/07-gateway/) (the listener and dispatcher).


## Rule families

Each endpoint claims requests and emits **actions** of a specific
family. Each action carries the family's facets, and rules match
against those facets. See [Architecture](/docs/04-architecture/) for
how endpoints claim requests in the first place.

### `http_rule`

Binds to `https` endpoints. The matcher consumes the parsed HTTP
request *before* it is forwarded upstream, after MITM has terminated
TLS.

Match keys (all optional, all combine with implicit AND):

```hcl
match = {
  method        = "POST"                            # HTTP verb (case-insensitive)
  path          = ["/v1/refunds", "/v1/payouts"]    # URL path; glob OK
  query         = { agent_id = "ci" }               # substring query-param match
  headers       = { "x-tenant" = "prod" }           # substring header match
  body_json     = { archived = true }               # JSON subset match
  body_contains = "BEGIN PRIVATE KEY"               # raw substring (case-sensitive)
  credential    = github-prod-pat                   # bare-name ref to the dispatched credential
}
```

### `sql_rule`

Binds to `sql` endpoints (`postgres`, `clickhouse_https`,
`clickhouse_native`). The matcher runs against every parsed SQL
statement the agent sends.

```hcl
match = {
  verb            = ["select", "show", "explain"]  # first verb of the statement
  tables          = ["users", "secret_*"]          # any extracted table satisfies the list; glob OK
  function        = ["pg_read_file", "dblink_*"]   # any extracted function satisfies the list; glob OK
  statement       = "ALTER SYSTEM *"               # whole-statement glob
  statement_regex = "(?i)\\bpassword\\b"           # whole-statement Go RE2 regex
  credential      = pg-readwrite                   # bare-name ref to the dispatched credential
}
```

`verb`, `tables`, and `function` are extracted by a best-effort
lexer — see "Gotchas" below.

`tables` and `function` are **multi-valued** facets: a single
statement can name several tables (`SELECT ... FROM a JOIN b`) and
call several functions. The rule fires when **at least one**
extracted name satisfies the list — i.e. matches at least one
positive glob and is not knocked out by a negative glob. So
`tables = ["users", "secret_*"]` fires on
`SELECT * FROM users JOIN orders` (because `users` matches), and
`tables = ["!audit_*"]` fires on any statement that touches at least
one table outside `audit_*`. To require *every* extracted name be
covered, write the rule against `statement_regex` instead.

### `k8s_rule`

Binds to `kubernetes` endpoints. The matcher receives the
`(verb, resource, namespace, name, params)` tuple Claw Patrol parses
out of the kubernetes API path.

`http_rule` does **not** bind to `kubernetes` endpoints — they are
in the `k8s` family and only accept `k8s_rule`. To express HTTP-level
intent against kubernetes traffic, write a `k8s_rule` against the
parsed `(verb, resource, namespace, name)` tuple.

```hcl
match = {
  resource   = ["pods/exec", "pods/attach"]   # `<resource>/<sub>` for subresources
  verb       = ["create", "delete"]           # HTTP-derived: list/get/create/update/patch/delete
  namespace  = ["console", "kube-system"]     # kubernetes namespace; glob OK
  name       = "!debug-*"                     # resource name; negation glob
  params     = { stdin = "true" }             # query-string params (kubectl exec --stdin)
  credential = k8s-prod                       # bare-name ref to the dispatched credential
}
```

Rules don't cross families: a `sql_rule` never fires on an HTTPS
request and vice versa. Each endpoint family declares its own match
facets, and the matching rule type binds to those facets.


## How to create a rule

Every rule shares the same outer skeleton. Field-by-field:

```hcl
rule "<type>" "<name>" {
  endpoint  = <endpoint-name>            # singular: bare-name ref
  # endpoints = [<a>, <b>]               # OR list form (mutually exclusive)

  priority  = 100                        # default 0; higher wins

  match     = { <family-specific keys> } # absent / empty == match-all

  verdict   = "allow"                    # OR
  # verdict = "deny"                     # OR
  # approve = [<approver>, ...]          # bare-name refs to approver blocks

  reason    = "destructive money movement"

  # disabled = true                      # keep in source, skip evaluation
}
```

| Field        | Required?                | Notes |
|--------------|--------------------------|-------|
| `endpoint` / `endpoints` | exactly one             | Bare-name refs to declared endpoints. The endpoint family must match the rule type. |
| `priority`   | optional (default `0`)   | Higher fires first. Negative for catch-alls (`-100` is the convention). |
| `match`      | optional                 | Object literal of family-specific keys. Absent or empty `{}` matches every request the endpoint sees. |
| `verdict`    | one of `verdict` / `approve` | `"allow"` or `"deny"`. |
| `approve`    | one of `verdict` / `approve` | List of approver bare names. Approvers run in order; **all must allow** for the request to proceed. |
| `reason`     | optional                 | Surfaced to the agent on `deny` / approver-deny, and shown on the dashboard. |
| `disabled`   | optional                 | Keeps the rule in source but suppresses it at compile time. |

Naming: every named entity in `gateway.hcl` (approvers, credentials,
endpoints, rules, profiles) shares **one flat namespace**. References
are bare names — never `endpoint.foo` or `credential.foo`. A
duplicate name across kinds is a load error.

A rule that names a wrong-family endpoint, an undeclared name, or a
typo in a match key fails at load time with an error pointing at the
offending block.


## Matching semantics

### Endpoint and action

Each endpoint plugin claims the requests it owns and emits an
**action** in its family — `https` actions for HTTPS endpoints, `sql`
actions for postgres / clickhouse, `k8s` actions for kubernetes.
Each action carries the family's facets (method/path/headers for
HTTPS, verb/tables/function for SQL, resource/verb/namespace for
k8s). Rules then match against those facets.

How an endpoint claims a given connection (SNI peek, destination IP,
profile scoping) is described in
[Architecture](/docs/04-architecture/). If no endpoint claims the
flow, no rule evaluation happens — the connection is passed through
verbatim.

### Priority and first-match-wins

Each endpoint's rules are sorted by priority at compile time
(descending — higher priority first). The runtime walks them in
order and returns the first rule whose matcher accepts the request.

Within a priority bucket, **declaration order is the tiebreaker**:
two rules at the same priority that both match — the one written
first in the HCL wins.

`disabled = true` rules are skipped entirely.

### Match facet semantics

Each match key takes either a single string or a list of strings.
Lists are "any-of":

```hcl
verb = ["create", "update", "patch"]    # matches any of the three
```

A leading `!` on a list element negates that element:

```hcl
resource = ["!*/exec", "!*/attach"]     # matches when neither glob matches
name     = ["debug-*", "!debug-prod"]   # matches debug-* AND not debug-prod
```

The list-with-negation rule. For the rule to trigger:

- If the list has **positive** entries, at least one must match.
- No **negative** entry may match.

`*` and `?` in a string make it a `path.Match` glob. `*` matches any
sequence of characters except the separator (`/`); `?` matches any
single character. There is no `**`, no character classes beyond
`[abc]`, no escape sequence.

`statement_regex` (SQL only) is a Go RE2 regular expression, run
**unanchored**. To require start-of-string add `^`; to require end
add `$`. Anchor your regex if you mean it.

### Case sensitivity, by facet

| Facet                      | Case sensitivity |
|----------------------------|------------------|
| HTTP `method`              | insensitive      |
| HTTP `path`, `query`, `headers` | sensitive   |
| HTTP `body_contains`       | sensitive        |
| SQL `verb`                 | insensitive      |
| SQL `tables`, `function`, `statement`, `statement_regex` | sensitive (matched against lower-cased SQL) |
| K8s `verb`                 | insensitive      |
| K8s `resource`, `namespace`, `name`, `params` | sensitive |

For SQL, the parser lower-cases the statement before extracting verbs,
tables, and functions — so `tables = "Users"` will never fire. Write
match keys in the same case the parser will produce (lower).

### `credential = X`

`credential` does not look at the request body or headers — it
matches the resolved credential name, not the credential's secret
contents.

### Outcome dispatch

After a rule matches:

- `verdict = "allow"` — the request is forwarded.
- `verdict = "deny"` — the request is rejected. HTTP gets a 403
  with `reason` in the body; postgres gets an `ErrorResponse` frame
  carrying `reason`.
- `approve = [a, b, c]` — approvers run in order, **all must allow**.
  The first non-allow approver short-circuits and is returned. An
  approver that returns no decision (e.g. timeout) is treated as deny.

LLM approvers call the configured model via its bound credential and
judge the request against the approver's policy. Human approvers park
the request on the dashboard's pending-approvals page. If the approver
block has a `credential` reference to a `slack_tokens` credential, Claw
Patrol also posts an approval message to the configured Slack channel.
By default the message carries a link back to the dashboard; setting
`interactive = true` on the approver embeds in-channel "approve" and
"deny" buttons so the reviewer can decide without leaving Slack.

If no rule matches, the request is **allowed** — there is no global
default-deny. Add a `priority = -100, verdict = "deny"` catch-all
per endpoint to invert this.


## Examples

### Allow / deny pair (HTTP)

A simple shape: read-only is free, deletes are blocked, everything
else needs a human.

```hcl
approver "human_approver" "billing" {
  channel = "#agent-billing"
  timeout = 600
}

endpoint "https" "stripe" {
  hosts      = ["api.stripe.com"]
  credential = stripe-key
}

rule "http_rule" "stripe-reads" {
  endpoint = stripe
  match    = { method = "GET" }
  verdict  = "allow"
}

rule "http_rule" "stripe-no-deletes" {
  endpoint = stripe
  match    = { method = "DELETE" }
  verdict  = "deny"
  reason   = "Stripe deletes go through the approval flow as POST"
}

rule "http_rule" "stripe-other-writes" {
  endpoint = stripe
  match    = { method = "POST" }
  approve  = [billing]
}

rule "http_rule" "stripe-default" {
  endpoint = stripe
  priority = -100
  verdict  = "deny"
}
```

The trailing `priority = -100` rule is the default-deny floor —
matched only when no higher-priority rule does. Without it, an
unmatched request would fall through and pass.

### Multi-credential endpoint with `credential = X` selector

One endpoint, two credentials, dispatched by an agent-side
placeholder:

```hcl
approver "human_approver" "billing" {
  channel = "#agent-billing"
  timeout = 600
}

credential "bearer_token" "orb-test-key" {}
credential "bearer_token" "orb-prod-key" {}

endpoint "https" "orb" {
  hosts = ["api.withorb.com"]
  credentials = [
    { placeholder = "PH_orb_test", credential = orb-test-key },
    { placeholder = "PH_orb_prod", credential = orb-prod-key },
  ]
}

rule "http_rule" "orb-test-allow-all" {
  endpoint = orb
  match    = { credential = orb-test-key }
  verdict  = "allow"
}

rule "http_rule" "orb-prod-reads" {
  endpoint = orb
  match    = { credential = orb-prod-key, method = "GET" }
  verdict  = "allow"
}

rule "http_rule" "orb-prod-writes" {
  endpoint = orb
  match    = { credential = orb-prod-key, method = ["POST", "PUT", "PATCH"] }
  approve  = [billing]
}

rule "http_rule" "orb-prod-deletes" {
  endpoint = orb
  match    = { credential = orb-prod-key, method = "DELETE" }
  verdict  = "deny"
}
```

`match.credential` fires when the request was *dispatched against*
that credential — i.e. the agent embedded `PH_orb_prod` in the
`Authorization: Bearer ...` slot. The matcher does not look at the
request body for the placeholder.

### LLM proctor → human approver chain

Approvers run in order, all must allow. The first approver is cheap
(an LLM judge), the second is expensive (a human gets paged):

```hcl
approver "llm_approver" "pg-secret-columns-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic-key
  policy     = pg-secret-columns
}
approver "human_approver" "console-dba" {
  channel = "#agent-db"
  timeout = 600
}
policy "pg-secret-columns" {
  text = <<-EOT
    Deny SELECTs that read raw secret material (tokens, password hashes,
    cert private keys). Allow metadata-only reads (id, name, created_at).
  EOT
}

rule "sql_rule" "pg-secret-columns" {
  endpoint = pg-deployng
  priority = 100
  match    = {
    verb   = "select"
    tables = ["github_identities", "tokens", "domain_certificates", "env_vars"]
  }
  approve = [pg-secret-columns-judge, console-dba]
}
```

If the LLM judge says `allow`, the request goes to `console-dba` for
human approval. If the LLM judge says `deny`, the human is never
paged. If either says `deny`, the request is rejected with the
reason returned by the rejecting approver.

The bare name `dashboard` is a built-in approver: `approve =
[dashboard]` parks the request on the dashboard's pending-approvals
view without paging any channel.

### SQL banned-verbs catch-all

```hcl
rule "sql_rule" "pg-banned-verbs" {
  endpoints = [pg-deployng, pg-scheduler]
  match     = { verb = ["drop", "truncate", "alter", "grant", "revoke", "vacuum", "create"] }
  verdict   = "deny"
  reason    = "Schema changes / destructive DDL not permitted; use a migration PR"
}
```

The same rule attaches to two endpoints. Both copies share the
compiled matcher — attaching a rule to N endpoints is cheap.

### Kubernetes negation glob

```hcl
rule "k8s_rule" "k8s-no-mutations" {
  endpoint = k8s-prod
  match = {
    verb     = ["create", "update", "patch", "delete"]
    name     = "!debug-*"
    resource = ["!*/exec", "!*/attach", "!*/portforward"]
  }
  verdict = "deny"
  reason  = "Only debug-* pods may be created / modified / deleted"
}
```

A negation entry is a leading `!`. List semantics with negation are
worth a careful read.


## Operational notes

### Testing rules

There is no `clawpatrol rules test` CLI today. To smoke-test a rule
against your real config: load the gateway locally, point an agent
at it, and watch the dashboard's per-action log. The log line
carries the matched rule name so you can confirm which rule fired.
