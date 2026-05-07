# Approval rules

Claw Patrol classifies every outbound action it intercepts and asks: should
this action be allowed, denied, deferred to a human, or deferred to an
LLM judge? The decision is made by a single rule engine — the **approval
rules** subsystem documented here.

This doc covers the rule shape, the pattern dialect used to match
actions, how decisions are dispatched, where rules are stored, and the
HTTP API surface used by the dashboard.

For the broader request flow see
[Architecture](/docs/04-architecture/) and
[Gateway](/docs/07-gateway/). For the agent trust boundary see
[Security Model](/docs/11-security-model/). For LLM cost concerns
referenced by the `require_llm` decision see
[Token Usage](/docs/09-token-usage/).


## Where rules sit

Every protocol the proxy understands -- HTTPS, SQL, SSH, Kubernetes,
WebSocket, plugin-defined -- lowers each request into a uniform
`ActionRecord`. Before the request is forwarded, the rule engine runs.

```
agent
  |
  |  outbound request (HTTPS / SQL / SSH / k8s / ...)
  v
proxy / plugin
  |
  |  emits ActionRecord
  v
+-------------------------------+
|  approvals/index.ts           |
|                               |
|  evaluate(rules, action)      |   <-- this doc
|    -> static allow            |
|    -> static deny             |
|    -> require_llm  --> LLM    |
|    -> require_human --> human |
|    -> default policy          |
+---------------+---------------+
                |
                |  ApprovalVerdict { decision, source, reason, ... }
                v
            forward / drop
```

The implementation lives in `src/approvals/`:

- `rules.ts` -- compilation + evaluation (this is the spec)
- `config.ts` -- SQLite row layer (`approval_rules` table)
- `index.ts` -- router that lowers `require_*` decisions to approver
  plugin calls
- `registry.ts` -- registry of approver plugins and per-plugin profiles
- `llm.ts` -- LLM approver driver (with verdict cache)
- `human.ts` -- in-memory pending-approval queue used by
  `dashboard-approval` and consumed by the dashboard's PendingActions
  page
- `webhooks.ts` -- inbound dispatch to approver-plugin webhooks
- `schema-catalog.ts` -- catalog of `ActionSchema` entries the dashboard
  rule builder reads to populate dropdowns


## Rule shape

A rule is a single row in the `approval_rules` SQLite table, compiled
into a `Rule` object at load time.

```typescript
interface Rule {
  id: string;
  label?: string;

  // Scope: any of these may be null. Null means "applies to anything".
  scopePluginId?: string | null;
  scopeProfileId?: string | null;
  scopeIntegrationId?: string | null;

  priority: number;        // higher wins
  enabled: boolean;
  dialect: "pattern";      // only dialect supported today
  when: unknown;           // matcher tree (see "The pattern dialect")
  decision: RuleDecision;  // allow | deny | require_llm | require_human

  source?: string;         // raw JSON of `when` (round-tripped to UI)
}
```

### Decision values

```typescript
type RuleDecision =
  | { kind: "allow" }
  | { kind: "deny"; reason?: string }
  | { kind: "require_llm";
      approverPluginId: string;
      approverProfileId: string;
      model: string;
      prompt: string;
      cacheTtlSeconds: number;
      failClosed: boolean }
  | { kind: "require_human";
      approverPluginId: string;
      approverProfileId: string;
      timeoutMs: number;
      onTimeout: "allow" | "deny" };
```

| Decision | Meaning |
|----------|---------|
| `allow` | Forward the request immediately. |
| `deny` | Block the request. `reason` is surfaced back to the agent and recorded on the action. |
| `require_llm` | Defer to an LLM approver plugin. The plugin returns a verdict; identical actions within `cacheTtlSeconds` reuse the verdict. If the approver call fails or times out (30s hard ceiling), `failClosed` decides: `true` denies, `false` allows. |
| `require_human` | Park the request and surface it to a human reviewer (dashboard or webhook-driven plugin). If no decision arrives within `timeoutMs`, `onTimeout` decides. |

### Scope

Scope narrows the set of sessions a rule applies to. Each session
carries a `pluginId`, `profileId`, and (optionally) `integrationId`.
A rule's scope field is matched against the session's corresponding
field; a `null` rule field is wildcard.

```typescript
function inScope(rule: Rule, session: SessionContext): boolean {
  if (rule.scopePluginId    && rule.scopePluginId    !== session.pluginId)    return false;
  if (rule.scopeProfileId   && rule.scopeProfileId   !== session.profileId)   return false;
  if (rule.scopeIntegrationId && rule.scopeIntegrationId !== session.integrationId) return false;
  return true;
}
```

Scope is *AND* across the three dimensions: a rule scoped to plugin
`github` AND profile `prod` only fires if both match.

### Priority and specificity

Rules are evaluated in this order:

1. Filter to enabled rules whose scope matches the session.
2. Sort by `priority` descending.
3. Within the same priority, sort by **specificity** descending:
   `integration` (4) > `profile` (2) > `plugin` (1) > global (0); the
   weights add (a plugin+profile-scoped rule has specificity 3).
4. Walk the sorted list and return the first rule whose `when` matches
   the action.

Two practical consequences:

- A high-priority global rule beats a low-priority integration-scoped
  rule. Use priority for "this should always win", not for ordering
  within the same logical band.
- At equal priority, the more specific rule wins. The dashboard surfaces
  this as: *"more specific scopes win at equal priority: integration >
  profile > plugin > global."*

### Default policy

If no rule matches, the engine falls back to the value of the
`CLAWPATROL_DEFAULT_POLICY` environment variable:

| Value | Behavior |
|-------|----------|
| `allow` (default) | Allow anything no rule denied. |
| `deny_writes` | Allow only `read` actions; deny `write`, `mutate`, and `destructive`. The verdict carries `source: "default"` and `reason: "default-deny for non-read actions"`. |

Default-policy verdicts have no `ruleId`. They are reported as
`source: "default"` in the action log.


## The pattern dialect

`when` is a tree. The leaves are *path → condition* pairs; the interior
nodes are boolean combinators.

### Paths

A path names a field of the `ActionRecord`. Two forms:

1. **Top-level fields** -- bare names map to top-level fields of the
   record:

   ```
   type        -- e.g. "http.request"
   summary     -- short human-readable summary
   description -- longer description (optional)
   verb        -- protocol verb (e.g. "DELETE", "SELECT")
   sensitivity -- "read" | "write" | "mutate" | "destructive"
   primary     -- name of the primary facet (e.g. "http")
   tags        -- string[] (any-of semantics for `contains` / `in`)
   ```

2. **Facet fields** -- everything else. The leading segment is treated
   as a facet key:

   ```
   "http.method"      -> $.facets.http.method
   "http.url"         -> $.facets.http.url
   "sql.verb"         -> $.facets.sql.verb
   "sql.tables"       -> $.facets.sql.tables
   "k8s.namespace"    -> $.facets.k8s.namespace
   "ssh.command"      -> $.facets.ssh.command
   ```

   The literal prefix `facets.` is also accepted and equivalent:
   `"facets.http.method"` resolves identically to `"http.method"`.

   Plugin-defined facets work the same way -- if a plugin emits a
   facet `slack`, then `"slack.channel"` resolves to
   `$.facets.slack.channel`.

The well-known facet keys are `http`, `ws`, `sse`, `llm`, `sql`, `ssh`,
`k8s`. Plugins may add more. The dashboard rule builder reads the
catalog from `/api/action-schemas` (see below) to populate field
dropdowns.

### Conditions

A condition either tests a value directly, or specifies an operator.

#### Literal sugar

A bare primitive is shorthand for `equals`:

```json
{ "http.method": "DELETE" }
```

is identical to:

```json
{ "http.method": { "equals": "DELETE" } }
```

A bare array literal has two semantics:

- if the value at the path is an array, the cond array must match
  element-for-element (set equality with order);
- otherwise, "value is one of":

```json
{ "http.method": ["GET", "HEAD"] }
```

For the common "one of" case prefer the explicit `in` form -- it works
with array-valued fields too (any-of semantics).

#### Operators

Every operator is keyed by its name in a single-key object:

| Operator | Example | Behavior |
|----------|---------|----------|
| `equals` | `{ equals: "DELETE" }` | Strict equality (`===`). |
| `in` | `{ in: ["GET", "HEAD"] }` | For scalars: value is in the array. For arrays (e.g. `tags`): any element overlaps. |
| `pattern` | `{ pattern: "^https://api\\.github\\.com/" }` | JS `RegExp` test. String-only. Invalid regex compiles to "no match". No flags. |
| `contains` | `{ contains: "/repos/" }` | Case-insensitive substring for strings; element membership for arrays. |
| `notContains` | `{ notContains: "test" }` | Inverse of `contains`. Returns `true` for non-string non-array values. |
| `glob` | `{ glob: "*.example.com" }` | Shell-style glob: `*` is `.*`, `?` is `.`, anchored. String-only. |
| `exists` | `{ exists: true }` | True iff the path resolves to a non-`null`, non-`undefined` value. `{ exists: false }` is its inverse. |

Notes:

- `contains` is **case-insensitive** when applied to strings; the array
  form is strict (uses `Array.includes`).
- `pattern` does not support flags. Inline them with the standard
  `(?i)` form -- e.g. `"(?i)delete"`.
- `glob` is a literal regex translation: only `*` and `?` are
  meta-characters. There is no `**` or character class support.
- An unknown operator key on a cond object means "no match" (silent).
  Misspell at your own risk; use the dashboard preview to catch this
  before saving.

### Combinators

```json
{ "http.method": "DELETE", "http.url": { "contains": "/repos/" } }   // implicit AND
{ "all": [ ... ] }                                                   // explicit AND
{ "any": [ ... ] }                                                   // OR
{ "not": { ... } }                                                   // NOT
```

`all` / `any` take an array of matchers. `not` takes a single matcher.
The implicit-AND form is the same as `all` over the keys: the rule
matches only if every key's condition matches.

`all`, `any`, `not` may appear at any depth. Mix freely with
implicit-AND keys at the same level:

```json
{
  "any": [
    { "http.method": "DELETE" },
    { "http.method": "PATCH" }
  ],
  "not": { "http.url": { "contains": "/sandbox/" } }
}
```


## Action schemas

The dashboard rule builder needs to know what facets and fields each
plugin emits. The endpoint `/api/action-schemas` returns the merged
catalog.

```bash
curl -s http://localhost:8080/api/action-schemas | jq
```

```json
{
  "schemas": [
    {
      "pluginId": "github",
      "type": "github.repo.delete",
      "label": "Delete repository",
      "description": "Permanently delete a GitHub repository.",
      "primary": "http",
      "defaultSensitivity": "destructive",
      "facets": ["http"]
    },
    {
      "pluginId": "postgres",
      "type": "sql.query",
      "label": "SQL query",
      "primary": "sql",
      "defaultSensitivity": "write",
      "facets": ["sql"]
    }
  ]
}
```

Each entry comes from a plugin's `actionSchemas` export -- plugins
declare their schemas through the plugin SDK; see
[Plugins](/docs/08-plugins/). The catalog only ships the facet *keys*,
not the full Zod schemas (Zod schemas are not JSON-serializable). The
rule builder uses these keys to surface the supported `<facet>.<field>`
prefixes.

To register new schemas, ship them on a plugin -- there is no separate
schema registration API. The catalog is rebuilt on every API call.


## Decision dispatch

After `evaluate()` selects a rule, `approvals/index.ts` lowers
`require_*` decisions to a real verdict:

```
                  evaluate()
                      |
       +--------------+--------------+
       |       |             |       |
     allow   deny       require_llm  require_human
       |       |             |             |
       v       v             v             v
   forward  return     reviewWithCache  requestHuman
            with         (llm.ts)       (human.ts)
            reason          |               |
                            v               v
                       LlmApproverPlugin  HumanApproverPlugin
                       .review(...)       .request(...)  /
                                          dashboard queue
```

### `require_llm`

`approvals/llm.ts` wraps the configured LLM approver plugin's
`review()` method:

- Cache key: `(action.type, action.primary, action.facets, prompt,
  model)`. Two identical actions within `cacheTtlSeconds` reuse the
  earlier verdict.
- The call is aborted after **30 seconds** regardless of the plugin's
  internal timeouts.
- On error or timeout: the `failClosed` flag on the rule's decision
  decides. `failClosed: true` returns `deny`; `false` returns `allow`.
  Both carry `source: "llm"` and a synthetic `reason`.
- On success, the plugin's verdict is propagated and stamped with the
  rule id and approver identity.

The cost of these reviews shows up in the request log like any other
LLM call -- see [Token Usage](/docs/09-token-usage/). Use the cache
TTL aggressively for repetitive actions.

### `require_human`

`approvals/human.ts` has two modes:

- **`dashboard-approval`** (built-in): the action is enqueued in an
  in-memory `pending` map, every SSE listener on
  `/api/pending-actions/stream` is notified, and the framework parks on
  a `Promise` until either the dashboard PendingActions page resolves
  the entry, or the timeout fires.
- **third-party** (Slack, email, etc.): the framework calls the
  plugin's `request()` method. The plugin owns its correlation state
  (a webhook from Slack arrives via `dispatchWebhook` in
  `src/approvals/webhooks.ts`, mounted at
  `/api/approvers/<plugin-id>/<path>`).

In both cases:

- The total wait is bounded by `timeoutMs`. For third-party plugins,
  the framework adds a one-second grace to the `AbortController`
  signal.
- On timeout the verdict is `{ decision: onTimeout, reason: "no
  response within <ms>ms" }`.
- On a verdict, the action proceeds (or is denied) and is logged with
  `source: "human"`, the rule id, and the approver identity.

Note: `dashboard-approval` keys pending entries by a fresh UUID rather
than the real action id (the action id isn't yet known when the router
is invoked). This UUID is what the dashboard sees and is what
`POST /api/pending-actions/<id>/decision` resolves.


## Rule storage

Rules live in the `approval_rules` table of the main SQLite database,
under `$CLAWPATROL_DATA/clawpatrol.db` (default `~/.clawpatrol/clawpatrol.db`). They are
**not** loaded from files on disk -- the dashboard is the only writer
in the supported path.

```sql
CREATE TABLE approval_rules (
  id               TEXT PRIMARY KEY,
  label            TEXT,
  scope_plugin_id  TEXT,
  scope_profile_id TEXT,
  scope_integration_id TEXT,    -- added in migration 0006
  priority         INTEGER NOT NULL,
  enabled          INTEGER NOT NULL DEFAULT 1,
  dialect          TEXT NOT NULL DEFAULT 'pattern',
  source           TEXT NOT NULL,   -- raw JSON of `when`
  compiled         TEXT,            -- reserved for future dialects
  decision         TEXT NOT NULL,   -- allow | deny | require_llm | require_human
  reason           TEXT,
  approver_plugin_id  TEXT,
  approver_profile_id TEXT,
  llm_prompt      TEXT,
  llm_model       TEXT,
  llm_cache_ttl_s INTEGER,
  llm_fail_closed INTEGER,
  timeout_ms INTEGER,
  on_timeout TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX rules_scope_idx
  ON approval_rules(scope_plugin_id, scope_profile_id, priority);
```

### Compiled cache and reload semantics

The router holds a process-local `cachedRules: Rule[]` snapshot. The
cache is rebuilt by `invalidateRules()`, which is called:

- Once at startup, from `installApprovalRouter()`.
- After every successful `POST /api/rules` (create or update).
- After every successful `DELETE /api/rules/<id>`.

In other words, dashboard edits are **hot** -- the very next action
sees the new rule set. There is no file watcher and no SIGHUP. If you
mutate the table out-of-band (direct SQLite write), call
`invalidateRules()` from a plugin or restart the process.

### Validation

Validation is intentionally thin:

- The HTTP layer trusts the body shape (TypeScript at the call site,
  no runtime schema). Bad payloads produce SQL errors or odd-but-safe
  rules.
- `compileRule()` parses `source` as JSON at load time. **Invalid JSON
  throws** -- and because rules are loaded as a batch, one corrupt
  row poisons the whole reload. The previous good cache stays in
  effect; the failure is logged as `[approvals] failed to reload
  rules: <error>`.
- Operator misuse (unknown operator key, wrong-typed argument,
  invalid regex) silently fails the match -- the rule never fires.
  Use the dashboard preview to catch this (see "Authoring rules
  in the dashboard").

The `compiled` column is reserved for non-pattern dialects (e.g. a
future expression dialect). Today it's always `NULL` and the dialect
is fixed at `"pattern"`.


## API surface

All endpoints are under `/api/` on the dashboard listener (default
`127.0.0.1:8080`). They require an authenticated session -- see
[Self-Hosting](/docs/06-self-hosting/) for how to drive them
programmatically with a session cookie.

### `GET /api/rules`

List every rule, ordered by `priority DESC, id`.

```bash
curl -s http://localhost:8080/api/rules | jq '.rules[0]'
```

```json
{
  "id": "0d8c...-...-...",
  "label": "deny prod deletes",
  "scope_plugin_id": "github",
  "scope_profile_id": null,
  "scope_integration_id": "int-prod",
  "priority": 100,
  "enabled": 1,
  "dialect": "pattern",
  "source": "{\"http.method\":\"DELETE\"}",
  "decision": "deny",
  "reason": "no prod deletes",
  ...
}
```

### `POST /api/rules`

Upsert a rule. With no `id`, a UUID is assigned and returned. With
`id`, the row is updated in place. The router cache is invalidated
before the response is sent.

```bash
curl -s -X POST http://localhost:8080/api/rules \
  -H 'content-type: application/json' \
  -d '{
    "label": "deny destructive SQL on prod",
    "scopeIntegrationId": "int-prod-pg",
    "priority": 100,
    "enabled": true,
    "source": "{\"sql.verb\":{\"in\":[\"DROP\",\"TRUNCATE\",\"DELETE\"]}}",
    "decision": "deny",
    "reason": "no destructive DDL on prod"
  }'
```

Response: `{ "id": "<uuid>" }`.

### `GET /api/rules/<id>`

Fetch one rule (the same shape as a list element).

### `DELETE /api/rules/<id>`

Delete a rule. Always returns `{ "ok": true }`, even if no row
matched. The router cache is invalidated.

### `POST /api/rules/preview`

Dry-run a draft rule against the most recent N actions logged in the
analytics store. Used by the dashboard's preview pane.

```bash
curl -s -X POST http://localhost:8080/api/rules/preview \
  -H 'content-type: application/json' \
  -d '{
    "draft": {
      "source": "{\"http.method\":\"DELETE\"}",
      "decision": "deny"
    },
    "lookbackLimit": 200
  }'
```

```json
{
  "matched": 12,
  "samples": [
    { "timestamp": "...", "sessionId": "...", "record": { ... } }
  ]
}
```

`lookbackLimit` is capped at 500. `samples` is capped at 20 entries.
The preview ignores scope -- it tells you whether the `when` matcher
would have hit; whether the rule would have *fired* depends on the
session's plugin/profile/integration at evaluation time.

### `GET /api/action-schemas`

The schema catalog used by the rule builder (see "Action schemas").

### `GET /api/approvers`

List registered approver plugins:

```json
{
  "llm": [{ "id": "anthropic-approver", "name": "...", "description": "..." }],
  "human": [{ "id": "dashboard-approval", "name": "...", "description": "..." }]
}
```

### Approver webhooks

```
/api/approvers/<plugin-id>/<path>
```

Mounted by `dispatchWebhook` in `src/approvals/webhooks.ts`. Forwarded
to the plugin's `webhooks[<path>]` handler. The plugin handles
signature verification and matches the inbound verdict to its parked
latch. Claw Patrol never inspects the body.

### Pending human approvals

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/pending-actions` | Snapshot of in-memory queue. |
| GET | `/api/pending-actions/stream` | SSE stream: pending entries + removals. |
| POST | `/api/pending-actions/<actionId>/decision` | Resolve a parked approval (`{ decision, reason?, reviewer? }`). |

Only entries from the `dashboard-approval` plugin live in this queue;
third-party human approvers manage their own state.


## Authoring rules in the dashboard

The dashboard's *Approval rules* page (component:
`dashboard/src/components/RulesPage.tsx`) is the supported authoring
surface.

The flow:

1. Click **New rule**. The editor opens with a blank draft (default:
   `{ "http.method": "DELETE" }`, decision `deny`, priority 100).
2. **Label** -- shown in the rule list.
3. **Scope** -- three dropdowns: plugin (filtered by what the schema
   catalog reports), profile (from `/api/profiles`), integration (from
   `/api/integrations`, filtered by selected plugin). Leaving all three
   empty is "global". Selecting plugin clears any integration that
   doesn't belong to that plugin.
4. **Priority** + **enabled** checkbox.
5. **Match (JSON)** -- the `when` matcher, edited as JSON. The hint
   under the textarea names the supported operators inline.
6. **Decision** dropdown -- selecting `require_llm` or `require_human`
   reveals the approver-specific fields (model, prompt, cache TTL,
   fail-closed flag for LLM; timeout, on-timeout for human).
7. **Preview** -- runs `/api/rules/preview` against the last 200
   actions. Surfaces "would have matched X of 200" and up to eight
   sample summaries. Use this to check for false positives before
   saving.
8. **Save** -- calls `POST /api/rules`. The list refreshes; the new
   rule is live for the next action.

Available action types are surfaced as a collapsed `<details>` block
at the bottom of the editor.

The list view shows label, scope, decision, priority, enabled, and
edit/delete affordances. Editing a rule rehydrates the draft with all
its fields; deleting is confirmed by browser `confirm()`.


## Worked examples

### Example 1: deny destructive SQL on a prod Postgres integration

Rule that fires when a session attached to integration `int-prod-pg`
runs any `DROP`, `TRUNCATE`, or `DELETE`.

```json
{
  "label": "no destructive DDL on prod",
  "scopeIntegrationId": "int-prod-pg",
  "priority": 100,
  "enabled": true,
  "source": "{\"sql.verb\":{\"in\":[\"DROP\",\"TRUNCATE\",\"DELETE\"]}}",
  "decision": "deny",
  "reason": "destructive SQL on prod is human-only"
}
```

Triggers: any action where the SQL plugin populates
`facets.sql.verb` with one of those values **and** the session is
scoped to integration `int-prod-pg`. Scope acts as the "where it
applies" filter; `when` is the "what it matches" predicate.

Result: the agent receives `ActionDeniedError` with the configured
reason; the action is logged with `source: "static"` and the rule id.

### Example 2: auto-allow read-only GET requests to internal docs

Allow any HTTP GET to a wiki host without prompting. Scoped globally,
high priority so it overrides any later "human approve all writes"
rule.

```json
{
  "label": "allow internal-wiki reads",
  "priority": 200,
  "enabled": true,
  "source": "{\"http.method\":\"GET\",\"http.url\":{\"glob\":\"https://wiki.internal.example/*\"}}",
  "decision": "allow"
}
```

Triggers: any HTTP request whose method is `GET` AND whose URL begins
with the configured prefix. Both keys must match (implicit AND).

Result: `source: "static"`, `decision: "allow"`, no approver call.

### Example 3: defer expensive LLM calls to a human

The pattern dialect cannot do numeric comparisons (see
"Limitations") so we cannot say "$ > 0.10" directly. The closest
expressible thing is "calls to expensive models", matched by model
name:

```json
{
  "label": "human-approve big-model calls",
  "scopePluginId": "anthropic",
  "priority": 50,
  "enabled": true,
  "source": "{\"any\":[{\"llm.model\":{\"glob\":\"claude-opus-*\"}},{\"llm.model\":{\"glob\":\"gpt-4*\"}}]}",
  "decision": "require_human",
  "approverPluginId": "dashboard-approval",
  "approverProfileId": "default",
  "timeoutMs": 300000,
  "onTimeout": "deny"
}
```

Triggers: any action carrying an `llm` facet whose `model` matches
either glob.

Result: the action is parked in the in-memory queue; the dashboard's
PendingActions page lights up; SSE listeners are notified. The agent
blocks for up to 5 minutes. If a reviewer denies, the agent receives
`ActionDeniedError` with their reason. If no one acts in 5 minutes,
`onTimeout: "deny"` denies the call.


## Operational notes

### Testing rules

There is no `clawpatrol rules test` CLI today. Use the dashboard preview
(`POST /api/rules/preview`) for dry runs against historical actions.

For unit tests, the engine itself is a pure function:

```typescript
import { evaluate, compileRule } from "./approvals/rules.js";

const rule = compileRule({ /* DB row */ });
const out = evaluate({ rules: [rule], defaultPolicy: "allow" }, action, session);
// out.verdict.decision in {"allow", "deny", "timeout"}
// out.rule is the matched Rule, or null for a default-policy verdict
```

`src/approvals/rules.test.ts` is the canonical reference for how each
operator and combinator behaves; treat the test cases as runnable
examples.

### Rolling back a rule

Three options, in order of preference:

1. **Disable** the rule from the dashboard (clear the *enabled*
   checkbox, save). The change is hot.
2. **Lower priority** below another rule that allows the action.
3. **Delete** the rule. Irreversible -- the row is gone.

For audit, every successful save updates `updated_at`; deletes leave
no audit trail in the table itself, but each `POST /api/rules` and
`DELETE /api/rules/<id>` is logged as a regular dashboard request and
shows up in the analytics store.

### Conflict reporting

There is no built-in conflict report today. The first matching rule
wins by the priority+specificity sort, and the verdict carries the
winning `ruleId`. To find which rule fired for a given action, look
at the action's logged verdict in the analytics view.


## Limitations

The pattern dialect is intentionally small. Known gaps:

- **No numeric comparison.** `>=`, `<=`, `>`, `<` are not implemented.
  Worked example 3 shows the workaround (match on a categorical proxy
  -- e.g. model name).
- **No time-of-day or calendar matching.** "Block on weekends" and
  "allow only during business hours" are not expressible.
- **No rate-based or sequence-based matching.** The engine sees one
  `ActionRecord` at a time; it cannot match "more than 10 deletes per
  minute".
- **No regex flags.** Use inline groups (`(?i)`) instead.
- **No `**` glob.** Only `*` (any sequence) and `?` (any single char).
- **No object equality.** Object-valued conditions are interpreted as
  operator objects, not literal values.
- **`pattern`, `glob`, and case-insensitive `contains` only apply to
  strings.** On non-string values they return false.
- **Single dialect.** The schema reserves a `compiled` column and a
  `dialect` field, but only `"pattern"` is implemented.
- **Validation is best-effort.** A misspelled operator key silently
  produces a rule that never fires.
- **Rule storage is dashboard-only.** No file-based rule definitions,
  no `git`-able rule files, no import/export endpoint.
- **`dashboard-approval` action ids are queue-local.** The id the
  dashboard sees is a UUID minted by `human.ts`, not the
  `ActionRecord` id; correlation between an audit-log entry and a
  pending-approvals entry has to go through the rule id and timestamp.

When you hit any of these, the typical response is to express the
intent more coarsely (e.g. "always require human for this action
type") and lean on the LLM approver for the contextual judgment.
