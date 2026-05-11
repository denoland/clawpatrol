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

### Priority override pattern

A high-priority allow / deny short-circuits a broader rule that
would otherwise fire at default priority:

```hcl
approver "human_approver" "billing" {
  channel = "#agent-billing"
  timeout = 600
}

# Priority 100 — fires before anything else.
rule "http_rule" "stripe-ephemeral-keys" {
  endpoint = stripe
  priority = 100
  match    = { method = "POST", path = "/v1/ephemeral_keys" }
  verdict  = "allow"
}

# Priority 0 (default) — would otherwise force every POST through approval.
rule "http_rule" "stripe-other-writes" {
  endpoint = stripe
  match    = { method = "POST" }
  approve  = [billing]
}
```

Ephemeral-key creation is whitelisted — every other POST still goes
through `billing`. Without the priority override, the broader rule
would page a human for every key issuance.

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
worth a careful read — see Gotchas below.


## Gotchas

This is the section to read carefully. Most of these are best-effort
parser limitations, schema-vs-runtime gaps, or surprising matcher
semantics.

### HTTP request bodies are capped at 1 MiB for matching

The gateway buffers up to 1 MiB of request body before evaluating
rules. Bytes beyond 1 MiB stream through to the upstream unbuffered
and are **invisible** to `body_contains` and `body_json`.

Practical effect: a `body_contains = "secret"` rule matches only if
the substring appears in the first 1 MiB of the body. Above that
size, the rule's outcome doesn't depend on body content. Most agent
traffic stays well below this; bulk file uploads are the obvious
exception.

### SQL `verb` matches only the first verb in a statement

The SQL parser takes the first whitespace-delimited token as `verb`.
A multi-statement query like:

```sql
SELECT 1; DROP TABLE users;
```

has `verb = "select"`. A `verb = "drop"` rule does **not** fire on
this query.

`tables`, `functions`, and `statement` / `statement_regex` see the
full statement text — so the `DROP` victim's table name *will* show
up under `tables`, and `statement_regex = "(?i)\\bdrop\\b"` *does*
match. Belt-and-braces banned-verb policies should pair `verb` with
`statement_regex`.

### SQL `tables` and `functions` are best-effort extractions

`tables` is extracted from `FROM`, `UPDATE`, `INTO`, and `JOIN`
clauses. `functions` is extracted as any identifier immediately
followed by `(`. Both run on the lower-cased statement.
Consequences:

- **CTEs are invisible** — `WITH t AS (...)` does not put `t` into
  `tables`. The actual `FROM t` after the CTE does.
- **Subqueries with table aliases** lose the alias's relationship
  to the underlying table.
- **Schema-qualified tables**: the extractor captures the dotted form
  (`schema.users`) so `tables = "users"` will not match
  `SELECT ... FROM schema.users`. Use a glob: `tables = ["*.users",
  "users"]`.
- **Schema-qualified function calls**: the extractor captures only the
  ident *immediately before* `(`, so `pg_catalog.pg_terminate_backend(...)`
  extracts as `pg_terminate_backend` — fine for banned-function lists.
- **Functions match aggressively**: anything-followed-by-`(`
  qualifies. `count(*)` puts `count` in `functions`.

If you need precise semantic SQL matching, lean on `statement_regex`
or implement the rule downstream of an LLM proctor.

### Postgres prepared statements are evaluated

Both simple queries and prepared-statement parses feed the matcher.
The parsed `verb` / `tables` / `function` come from the SQL text,
not from the protocol shape — a prepared `SELECT $1 FROM users` is
matched the same way as a simple `SELECT 1 FROM users`.

### ClickHouse native: every Query is evaluated

The `clickhouse_native` runtime decodes every query packet on the
wire and runs it through the matcher. Compressed inserts are
forwarded opaquely after their parent query has been allowed.

### `statement_regex` is unanchored

```hcl
statement_regex = "drop"
```

matches any statement containing `drop` anywhere — including
`SELECT 'drop' AS t`. Anchor with `^` / `$` if you want strict-prefix
or full-match semantics. The flavor is Go RE2; PCRE features
(backreferences, lookbehind) are unavailable. Inline flags (`(?i)`)
work.

### `body_json` only matches JSON-shaped bodies

`body_json` parses the buffered prefix as JSON. A body that's empty,
malformed JSON, or non-JSON content (form-encoded, multipart, raw
bytes) silently **fails the match** — the rule never fires. Pair it
with a `headers = { "content-type" = "application/json" }` sibling
if you want a clearer signal.

The match itself is a strict subset: every key/value in `body_json`
must appear in the body (extra keys in the body are fine, missing
keys fail). Lists in `body_json` are order-insensitive subsets.

### HTTP `headers` and `query` use substring matching

A rule like:

```hcl
match = { headers = { "x-tenant" = "prod" } }
```

matches `x-tenant: prod` **and** `x-tenant: production` **and**
`x-tenant: prod-east-1`. To pin to exact equality, write a longer
`want` that wouldn't be a substring of any other value. There is no
`equals`-only mode for headers today; file a bead if your policy
hinges on it.

### HTTP `Host` header isn't trustworthy for matching

The gateway resolves the upstream from the SNI hostname **before**
running rules, but the `Host` header still carries the agent's value
at match time. The Host-overwrite to the canonical upstream happens
later, just before forwarding. So `headers = { host = "api.github.com" }`
reads the agent-supplied header, not the trusted-from-SNI value.
Don't rely on it for authorization.

### K8s verbs are HTTP-method-derived, not real k8s verbs

`k8s_rule.match.verb` is synthesised from the HTTP method:

| HTTP   | k8s `verb` |
|--------|-----------|
| GET (no name)   | `list`   |
| GET (with name) | `get`    |
| POST   | `create` (incl. `pods/exec`) |
| PUT    | `update` |
| PATCH  | `patch`  |
| DELETE | `delete` |

There is **no `watch` verb**, and no
`drain` / `cordon` / `evict` / `scale` — those don't appear at the
HTTP layer in the same form. A rule asking for them never fires.
Match on `resource` (e.g. `pods/eviction`, `pods/scale`) instead.

### Negation glob lists are per-element

A common misread:

```hcl
name = ["allowed", "!debug-*"]
```

This is **not** "name in {allowed} AND name not in {debug-*}". It
is a list with one positive entry (`allowed`) and one negative entry
(`!debug-*`). Evaluation:

- If `name == "allowed"` and not glob-`debug-*`, both pass → match.
- If `name == "debug-prod"`, the negative fires → no match (regardless
  of the positive).
- If `name == "anything-else"`, the positive doesn't match and the
  negative doesn't fire → no match.

The list is **AND of element predicates** — every positive must
have at least one match, and no negative may match. Splitting
positives and negatives across rules is usually clearer.

### `defaults.unknown_host`, `llm_fail_mode`, `llm_cache_ttl`, `human_on_timeout` are schema-only today

The `defaults {}` block accepts these fields and they round-trip
through dump / emit, but only `human_timeout` is actually consulted
at runtime. The rest are reserved for future wiring. Behavior today,
regardless of what you set:

| Setting             | Configured  | Actual runtime behavior |
|---------------------|-------------|-------------------------|
| `unknown_host`      | (any)       | Passthrough — unmatched hostnames are forwarded verbatim. |
| `llm_fail_mode`     | (any)       | Closed — LLM API errors / timeouts deny. |
| `llm_cache_ttl`     | (any)       | No verdict cache — every approval call hits the LLM. |
| `human_on_timeout`  | (any)       | Deny — a human approver that doesn't respond before its timeout returns deny. |
| `human_timeout`     | seconds     | **Wired**: per-approver `timeout` overrides this default. |

Production policy that depends on any of the unwired fields has to
encode the intent another way (e.g. an explicit `verdict = "deny"`
catch-all instead of relying on `unknown_host = "deny"`).

### `device {}` blocks are not yet supported

Per-device override blocks (`device "<ip>" { rule ... }`) are on the
roadmap but not currently accepted by the parser — you'll get an
"Unsupported block type" diagnostic at load time. Today, scope
policy by **profile** instead.

### `approve` entries must be bare names

Struct-form entries (e.g. inline `policy` and `cache_ttl` on the
approver reference) are rejected by the current decoder:

```
Rule "X" approve stage must be a bare-name reference.
Bind policy text on the approver block itself.
```

Put the policy and any LLM-specific tuning on the `approver` block
and reference it by bare name from the rule.

### Empty `match` matches everything

```hcl
rule "http_rule" "deny-all-fallback" {
  endpoint = stripe
  priority = -100
  verdict  = "deny"
}
```

No `match` block means "match every request reaching this endpoint".
Combined with the lowest-possible priority, this is the
default-deny pattern. Make sure your high-priority allow rules
exist before relying on it.

### Names live in a single namespace

`approver "human_approver" "stripe"` and `endpoint "https" "stripe"`
collide — both register the bare name `stripe`. The loader rejects
the second declaration with a duplicate-name diagnostic. When in
doubt, prefix-name within a kind: `stripe-billing` (approver),
`stripe-api` (endpoint), `stripe-no-deletes` (rule).

### Rules attach to endpoints, not profiles

A rule does not name a profile; it names an endpoint. A profile
"opts in" to a rule by listing the rule's endpoint. Two profiles
that share an endpoint share the rule. To diverge per-profile, use
distinct endpoints (often differing only in name and `credential`)
and attach distinct rules to each.


## Operational notes

### Testing rules

There is no `clawpatrol rules test` CLI today. To smoke-test a rule
against your real config: load the gateway locally, point an agent
at it, and watch the dashboard's per-action log. The log line
carries the matched rule name so you can confirm which rule fired.

### Rolling back a rule

Two options:

1. **Disable** by adding `disabled = true` to the rule body. The rule
   stays in source for review; reload to take effect.
2. **Delete** by removing the block and reloading.

Both require a config reload (the gateway re-reads `gateway.hcl` on
SIGHUP / dashboard save).

### Where matched rules show up

Every action's verdict carries the matched rule name. The dashboard
surfaces this on the per-request page; the JSON API exposes it on
`/api/actions/<id>` (see [Self-Hosting](/docs/06-self-hosting/)).
Default-policy outcomes (no rule matched) carry an empty rule name.
