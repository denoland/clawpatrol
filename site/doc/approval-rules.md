# Approval rules

Rules are how an operator decides what happens to a request:
forward it, reject it, or route it through one or more
**approvers** — a human acting from the dashboard or Slack, an
LLM judging against a policy, or both in sequence (every approver
must allow). Each rule is a block in `gateway.hcl` that targets
one or more [endpoints](/docs/glossary/#endpoint), describes
which requests it applies to (the `condition` CEL expression),
and declares the outcome (`verdict = "allow" / "deny"`, or
`approve = [...]`).

There is one rule kind. The rule's protocol **family** — `http`,
`sql`, or `k8s` — is inferred from its endpoint(s) at load time and
pins the set of CEL variables the `condition` may reference. An
`https` endpoint exposes `http.method` / `http.path` / …; a postgres
or clickhouse endpoint exposes `sql.verb` / `sql.tables` / …; a
kubernetes endpoint exposes `k8s.verb` / `k8s.resource` / …. A rule
whose `endpoints = [...]` mixes families is a load error.

This page covers the operator's view: how to write a rule, what
each facet does, and how rules behave in different situations.

For the surrounding picture see
[Architecture](/docs/architecture/) — request flow, where matching
fits, how endpoints claim requests.


## Rule families

Each endpoint claims requests and emits **actions** of a specific
family. Each action carries the family's facets, and rules match
against those facets via a CEL `condition` expression. See
[Architecture](/docs/architecture/) for how endpoints claim requests
in the first place.

### `http` family

Bound to `https` endpoints. The condition is evaluated against the
parsed HTTP request *before* it is forwarded upstream, after MITM
has terminated TLS.

CEL variables (all optional in any given condition):

| Variable | Type | Description |
|----------|------|-------------|
| `http.method` | `string` | HTTP verb. Lowercased at activation time; literal `'POST'` in rule source is normalized to `'post'` at compile time so either case works. |
| `http.path` | `string` | Request path (no query string) |
| `http.query` | `map<string, list<string>>` | Query parameters (multi-valued) |
| `http.headers` | `map<string, list<string>>` | Request headers (multi-valued) |
| `http.body` | `string` | Raw request body |
| `http.body_json` | `dyn` | Parsed JSON body (when `Content-Type` is JSON) |

```hcl
condition = "http.method == 'POST' && http.path in ['/v1/refunds', '/v1/payouts']"
condition = "http.method in ['GET', 'HEAD']"
condition = "http.body.contains('BEGIN PRIVATE KEY')"
condition = "http.body_json.archived == true"
```

### `sql` family

Bound to `sql` endpoints (`postgres`, `clickhouse_https`,
`clickhouse_native`). The condition runs against every parsed SQL
statement the agent sends.

| Variable | Type | Description |
|----------|------|-------------|
| `sql.verb` | `string` | First verb of the statement (lower-case: `"select"`, …) |
| `sql.tables` | `list<string>` | Tables referenced by the statement |
| `sql.functions` | `list<string>` | Functions called by the statement |
| `sql.statement` | `string` | The full lower-cased statement text |
| `sql.database` | `string` | Agent-declared target database. Postgres reads it from the StartupMessage `database` (with `user` fallback). clickhouse_native reads `Hello.Database`. clickhouse_https reads `?database=` query first, then `X-ClickHouse-Database` header. Empty when neither set. |

```hcl
condition = "sql.verb in ['select', 'show', 'explain']"
condition = "'secrets' in sql.tables"
condition = "sets.intersects(sql.tables, ['users', 'audit_log'])"
condition = "sql.statement.matches('(?i)\\bpassword\\b')"
condition = "sql.database == 'prod'"
```

`verb`, `tables`, and `functions` are extracted by a best-effort
lexer over a lower-cased copy of the statement — see
[Case sensitivity](#case-sensitivity-by-variable) below.

`tables` and `functions` are **multi-valued** facets: a single
statement can name several tables (`SELECT ... FROM a JOIN b`) and
call several functions. Use CEL's `in` operator for a single name
(`'secrets' in sql.tables`) or `sets.intersects(...)` for an overlap
test against a list. To require *every* extracted name be covered,
write the condition against `sql.statement` with a regex
(`sql.statement.matches(...)`).

### `k8s` family

Bound to `kubernetes` endpoints. The condition sees the
`(verb, resource, namespace, name, params)` tuple Claw Patrol parses
out of the kubernetes API path.

| Variable | Type | Description |
|----------|------|-------------|
| `k8s.verb` | `string` | HTTP-derived verb (`"list"`, `"get"`, `"create"`, …) |
| `k8s.resource` | `string` | `<resource>` or `<resource>/<sub>` for subresources |
| `k8s.namespace` | `string` | Kubernetes namespace |
| `k8s.name` | `string` | Resource name |
| `k8s.params` | `map<string, string>` | Query-string params (e.g. `kubectl exec --stdin`) |

```hcl
condition = "k8s.verb in ['create', 'delete'] && k8s.resource == 'pods'"
condition = "k8s.resource in ['pods/exec', 'pods/attach']"
condition = "!k8s.name.startsWith('debug-')"
condition = "!k8s.resource.endsWith('/exec') && !k8s.resource.endsWith('/attach')"
```

A rule bound to `https` endpoints sees `http.*` only; a rule bound
to `kubernetes` endpoints sees `k8s.*` only. Mixing families across
a rule's `endpoints = [...]` is a load error.

`ssh` endpoints exist but have no rule family yet — the gateway
terminates auth and splices channels as opaque byte streams, emitting
a single `allow` event at session start. Rules cannot gate anything
inside an SSH session today.


## How to create a rule

Every rule shares the same outer skeleton. Field-by-field:

```hcl
rule "<name>" {
  endpoint   = <endpoint-name>            # singular: bare-name ref
  # endpoints = [<a>, <b>]                # OR list form (mutually exclusive)

  priority   = 100                        # default 0; higher wins

  credential = <credential-name>          # optional: only match when
                                          # the dispatched credential is this one

  condition  = "<CEL expression>"         # absent / empty == match-all

  verdict    = "allow"                    # OR
  # verdict  = "deny"                     # OR
  # approve  = [<approver>, ...]          # bare-name refs to approver blocks

  reason     = "destructive money movement"

  # disabled = true                       # keep in source, skip evaluation
}
```

| Field        | Required?                | Notes |
|--------------|--------------------------|-------|
| `endpoint` / `endpoints` | exactly one             | Bare-name refs to declared endpoints. All endpoints must share one protocol family. |
| `priority`   | optional (default `0`)   | Higher fires first. Negative for catch-alls (`-100` is the convention). |
| `credential` | optional                 | Bare-name ref. The runtime treats it as an extra predicate evaluated before the CEL condition: the request must have been dispatched against this credential. |
| `condition`  | optional                 | A CEL string evaluated against the family's variable set. Absent or empty matches every request the endpoint sees. |
| `verdict`    | one of `verdict` / `approve` | `"allow"` or `"deny"`. |
| `approve`    | one of `verdict` / `approve` | List of approver bare names. Approvers run in order; **all must allow** for the request to proceed. |
| `reason`     | optional                 | Surfaced to the agent on `deny` / approver-deny, and shown on the dashboard. |
| `disabled`   | optional                 | Keeps the rule in source but suppresses it at compile time. |

Naming: every named entity in `gateway.hcl` (approvers, credentials,
endpoints, rules, profiles) shares **one flat namespace**. References
are bare names — never `endpoint.foo` or `credential.foo`. A
duplicate name across kinds is a load error.

A rule that names an undeclared endpoint, mixes endpoint families,
or has a CEL expression that references variables not in the
inferred family fails at load time with an error pointing at the
offending block.


## Matching semantics

### Endpoint and action

Each endpoint plugin claims the requests it owns and emits an
**action** in its family — `http` actions for HTTPS endpoints, `sql`
actions for postgres / clickhouse, `k8s` actions for kubernetes.
Each action populates the family's CEL variables (method/path/headers
for HTTP, verb/tables/functions for SQL, resource/verb/namespace for
k8s). The rule's `condition` is evaluated against those variables.

How an endpoint claims a given connection (SNI peek, destination IP,
profile scoping) is described in
[Architecture](/docs/architecture/). If no endpoint claims the
flow, no rule evaluation happens — the connection is passed through
verbatim.

### Priority and first-match-wins

Each endpoint's rules are sorted by priority at compile time
(descending — higher priority first). The runtime walks them in
order and returns the first rule whose `credential` predicate (if
set) matches and whose CEL `condition` evaluates true.

Within a priority bucket, **declaration order is the tiebreaker**:
two rules at the same priority that both match — the one written
first in the HCL wins.

`disabled = true` rules are skipped entirely.

### CEL condition basics

Each family exposes one struct-typed top-level variable. Fields are
accessed with dot notation. Common idioms:

- **Equality / membership**: `http.method == 'POST'`,
  `sql.verb in ['select', 'show']`.
- **Prefix / suffix / substring**: `k8s.name.startsWith('debug-')`,
  `k8s.resource.endsWith('/exec')`, `http.body.contains('secret')`.
- **Regex** (when prefix / suffix isn't enough):
  `sql.statement.matches('(?i)\\bpassword\\b')`. Regex is unanchored
  Go RE2 — add `^` / `$` if you mean it.
- **List intersection** (any-of against a multi-valued facet):
  `sets.intersects(sql.tables, ['users', 'audit_log'])`. The `sets`
  extension is registered on every facet env.
- **Negation**: prepend `!` to any boolean expression.
  `!k8s.name.startsWith('debug-')`.

### Case sensitivity, by variable

| Variable                      | Case sensitivity |
|-------------------------------|------------------|
| `http.method`                 | lower-case (rule-source literals normalized at compile time) |
| `http.path`, `http.query`, `http.headers`, `http.body` | as on the wire |
| `sql.verb`                    | lower-case (normalized) |
| `sql.tables`, `sql.functions` | lower-case (extracted from a lower-cased copy of the statement) |
| `sql.statement`               | as on the wire (raw text, no case folding) |
| `sql.database`                | as on the wire (StartupMessage / Hello / HTTP query+header) |
| `k8s.verb`                    | lower-case (normalized) |
| `k8s.resource`, `k8s.namespace`, `k8s.name`, `k8s.params` | as on the wire |

For SQL, the parser lower-cases an internal copy of the statement
before extracting verbs, tables, and functions — so
`'Users' in sql.tables` will never fire. Write literals in the same
case the parser will produce (lower). `sql.statement` itself is the
raw on-the-wire text; match it case-blindly with a `(?i)` regex
flag (`sql.statement.matches('(?i)\\bpassword\\b')`).

### `credential = X`

`credential` is a top-level attribute on the rule, not part of the
CEL condition. It does not look at the request body or headers — it
matches the resolved credential name, not the credential's secret
contents. It is checked *before* the CEL condition.

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

### Async retry grants for agent clients

HTTP clients that can poll and retry may opt into async HITL grants.
This keeps normal transparent behavior when the reviewer answers
quickly, but avoids holding a long-lived upstream mutation request open
forever while a human is still deciding.

Async mode is deliberately narrow. It is used only when all of these are
true:

- the active profile sets `hitl_async_grants = true`;
- the matched human approver sets `sync_wait_timeout` and
  `async_grant { enabled = true }`;
- exactly one async-capable human approver stage is involved;
- the gateway has `public_url` configured so clients can poll status;
- the HTTP request body can be fingerprinted in `raw` mode without
  truncation or exceeding `max_body_bytes`.

With those conditions met, Claw Patrol first waits up to
`sync_wait_timeout`. If the human approves during that window, the
original request is forwarded normally. If the human denies, the request
is rejected normally. If the window expires first, Claw Patrol returns
`202 Accepted` and does **not** call upstream. The JSON response includes
`upstream_called = false`, `operation_id`, `status_url`, and a
`retry_original_request` hint that tells the client to keep polling
instead of treating the mutation as successful:

```json
{
  "operation_id": "hitl_op_...",
  "state": "pending_approval",
  "status_url": "https://gateway.example.test/api/hitl/operations/hitl_op_.../status",
  "upstream_called": false,
  "retry_original_request": true
}
```

Agent clients should poll `status_url` using their peer API token. When
the operation reaches `approved_waiting_for_retry`, the status response
adds the retry header pair:

```json
{
  "state": "approved_waiting_for_retry",
  "retry_header_name": "Clawpatrol-HITL-Operation",
  "retry_header_value": "hitl_op_..."
}
```

At that point, retry the original mutation with the same method, URL,
body, credential binding, and the `Clawpatrol-HITL-Operation` header
value from the status response. Claw Patrol
strips that internal header before forwarding upstream. Fingerprint or
auth-binding mismatches do not reuse the grant and should not be treated
as success. A retry grant is one-shot and expires after
`approved_retry_ttl`; a pending approval expires after `approval_ttl`.

If no rule matches, the request is **allowed** — there is no global
default-deny. Add a `priority = -100, verdict = "deny"` catch-all
per endpoint to invert this.


## Inspection-buffer overflow

To bound memory, the wire endpoints cap how much of each request they
buffer for the matcher. A request that exceeds its cap is **not**
dropped on the floor — the frame still forwards to upstream
byte-for-byte. What's bounded is the matcher's view of it: the
endpoint truncates the buffered slice and flags the request as
truncated. The facet fields that draw their value from this slice
are **truncatable facet fields** (listed per-endpoint in the table
below). When a rule's CEL reads a truncatable facet field on a
request that was flagged truncated, the rule is automatically
matched without comparing the matching values, and the dispatcher
returns a deny verdict for it.

| Endpoint | Inspected slice | Cap | Truncatable facet fields |
|----------|-----------------|-----|--------------------|
| `https` | request body on `POST` / `PUT` / `PATCH` | 1 MiB | `http.body`, `http.body_json` |
| `kubernetes` | request body on `POST` / `PUT` / `PATCH` | 1 MiB | *(none — every `k8s.*` facet is derived from the URL and method)* |
| `clickhouse_https` | request body on `POST` / `PUT` / `PATCH` | 1 MiB | `sql.verb`, `sql.tables`, `sql.functions`, `sql.statement` |
| `postgres` | `Query` (`Q`) and `Parse` (`P`) frame | 1 MiB | `sql.verb`, `sql.tables`, `sql.functions`, `sql.statement` |
| `clickhouse_native` | `Query` packet body | 1 MiB | `sql.verb`, `sql.tables`, `sql.functions`, `sql.statement` |

The caps are per-plugin constants in the gateway source — **not
operator-tunable** today, and not surfaced in `gateway.hcl`. Header
and URL bytes are bounded separately by `net/http`'s defaults and
aren't covered here; the `ssh` endpoint has no rule family, so no
inspection cap.

### Rule matching semantics on truncated fields

When a request overflows its cap, the dispatcher walks the endpoint's
rules in priority order as usual. For each rule:

- **Catch-all rule** (no `condition`): fires as written. A truncated
  body can't poison a rule that reads nothing.
- **Rule whose CEL reads no truncatable facet field** (e.g.
  `http.method == 'GET'`, `credential = X`, any `k8s.*` predicate):
  the matcher runs normally — the truncated bytes are irrelevant to
  its decision.
- **Rule whose CEL reads a truncatable facet field**: the rule is
  automatically matched without comparing the matching values. The
  dispatcher synthesizes a deny attributed to that rule, with this
  exact reason:

  ```
  rule "<name>" reads a request facet whose bytes were truncated by the gateway's inspection buffer; failing closed
  ```

  The synthesized rule keeps the original rule's name and priority,
  so logs and dashboards still attribute the deny to the rule whose
  contract the truncation broke.

The upshot: a rule matching on `http.method` and/or `credential` on
an `https` endpoint still fires on a 2 MiB body, but a
`http.body_json.field == "x"` rule auto-denies.

A matched rule with `approve = [...]` on a truncated postgres frame
is forced to deny without paging the approver (HITL can't reason about
bytes that aren't there); the postgres endpoint surfaces this with the
reason `"approval required but request was truncated by inspection
buffer"`.

### How the deny reaches the agent

Each protocol synthesizes the deny in its native shape so the agent's
driver doesn't disconnect:

- **`https`, `kubernetes`, `clickhouse_https`** — `HTTP/1.1 403
  Forbidden`, `Content-Type: text/plain`, reason in the body,
  `Connection: close`.
- **`postgres`** — `ErrorResponse` (severity `ERROR`, SQLSTATE
  `42501`, message = reason), followed by `ReadyForQuery` in idle
  state. The session stays open; the agent can run the next query.
- **`clickhouse_native`** — server `Exception` packet with the
  reason. The unread tail of the oversize `Query` body is drained off
  the wire so the next packet frames correctly.

### Why fail-closed

A truncated body might contain content that *would* have triggered a
deny rule the gateway can't see, so refusing is the safe default. If
legitimate traffic is expected to exceed the cap, write the rules
against non-truncatable facet fields only (see the table above) — those
rules still match on a truncated request and won't auto-deny.


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

rule "stripe-reads" {
  endpoint  = stripe
  condition = "http.method == 'GET'"
  verdict   = "allow"
}

rule "stripe-no-deletes" {
  endpoint  = stripe
  condition = "http.method == 'DELETE'"
  verdict   = "deny"
  reason    = "Stripe deletes go through the approval flow as POST"
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

rule "orb-prod-writes" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "http.method in ['POST', 'PUT', 'PATCH']"
  approve    = [billing]
}

rule "orb-prod-deletes" {
  endpoint   = orb
  credential = orb-prod-key
  condition  = "http.method == 'DELETE'"
  verdict    = "deny"
}
```

The top-level `credential = orb-prod-key` fires when the request was
*dispatched against* that credential — i.e. the agent embedded
`PH_orb_prod` in the `Authorization: Bearer ...` slot. The matcher
does not look at the request body for the placeholder.

### Multi-credential endpoint dispatched by database

For SQL endpoints (postgres, clickhouse_native, clickhouse_https), a
credential entry can claim only requests against specific databases
via `database = "X"` or `databases = ["X","Y"]`. Combine with
`placeholder = "..."` for two-axis dispatch (e.g. read-only credential
against prod):

```hcl
credential "clickhouse_credential" "ch-dev"  {}
credential "clickhouse_credential" "ch-prod" {}

endpoint "clickhouse_native" "ch-o11y" {
  hosts = ["clickhouse-o11y.example"]
  credentials = [
    { database  = "prod",        credential = ch-prod },
    { databases = ["dev", "qa"], credential = ch-dev  },
  ]
}

rule "ch-prod-readonly" {
  endpoint   = ch-o11y
  credential = ch-prod
  condition  = "sql.verb in ['select', 'show', 'explain']"
  verdict    = "allow"
}
```

An entry matches iff every constraint it declares is satisfied
(placeholder match AND database match). Among matches the
**most-specific** (highest constraint count) wins. Conflicting
constraint signatures are rejected at policy load — see the
`error_credentials_*` test fixtures for the diagnostics. An entry
with no constraints is the catchall; only one is allowed per list.

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

rule "pg-secret-columns" {
  endpoint  = pg-deploy
  priority  = 100
  condition = "sql.verb == 'select' && sets.intersects(sql.tables, ['github_identities', 'tokens', 'domain_certificates', 'env_vars'])"
  approve   = [pg-secret-columns-judge, console-dba]
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
rule "pg-banned-verbs" {
  endpoints = [pg-deploy, pg-scheduler]
  condition = "sql.verb in ['drop', 'truncate', 'alter', 'grant', 'revoke', 'vacuum', 'create']"
  verdict   = "deny"
  reason    = "Schema changes / destructive DDL not permitted; use a migration PR"
}
```

The same rule attaches to two endpoints. Both copies share the
compiled matcher — attaching a rule to N endpoints is cheap.

### Kubernetes negation

```hcl
rule "k8s-no-mutations" {
  endpoint  = k8s-prod
  condition = "k8s.verb in ['create', 'update', 'patch', 'delete'] && !k8s.name.startsWith('debug-') && !k8s.resource.endsWith('/exec') && !k8s.resource.endsWith('/attach') && !k8s.resource.endsWith('/portforward')"
  verdict   = "deny"
  reason    = "Only debug-* pods may be created / modified / deleted"
}
```

CEL's `!` operator negates any boolean subexpression — there's no
list-level negation syntax. Combine `&&` and `!` to express
"matches the broad pattern, but not these exceptions."
