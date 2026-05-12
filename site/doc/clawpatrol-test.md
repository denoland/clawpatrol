# `clawpatrol test`

A regression-test CLI for policy changes. It replays recorded
gateway actions against a candidate HCL policy and tells you whether
any verdict drifted — a `deny` that's now `allow`, a `pg-reads` rule
that no longer fires, an endpoint default that quietly changed.

It's a pure CLI: no gateway, no database, no auth. Drop the binary
into CI and run it on every push.

```bash
clawpatrol test <config.hcl> <fixture.json | fixture-dir>
```

Exit 0 when every fixture matches; 1 on any mismatch or fixture
load error; 2 on usage or config-load error.

## Workflow

1. **Run a gateway locally** against the policy you want to
   regression-test:

   ```bash
   clawpatrol gateway -config myconfig.hcl
   ```

2. **Send real requests through it.** Mix verdicts — drive the
   `allow` rules, drive the `deny` rules, drive any approver
   chains — so the corpus covers every comparison branch you care
   about.

3. **Click "Download action"** on each row's detail page in the
   dashboard. The browser saves a single `.json` file per action.

4. **Drop the files into a fixtures directory** and check them
   into your repo.

5. **Run the test:**

   ```bash
   clawpatrol test myconfig.hcl fixtures/
   ```

   Expect `N actions checked, 0 mismatches`.

6. **Make a policy change** and re-run. If a verdict moved, the
   runner prints the affected fixture and the `want` / `got` diff.

The same fixtures become CI's regression set on every push.

## Fixture format

Each fixture has two top-level keys: `match` is the assertion (what
the rule engine should produce); `action` is the recorded request
(what the agent did). Exactly one facet block (`http` / `k8s` /
`sql`) lives under `action`, carrying that facet's vocabulary —
the same fields your CEL rule conditions read.

```json
{
  "match": {
    "verdict":  "allow",
    "rule":     "public-readonly",
    "endpoint": "github"
  },
  "action": {
    "host":       "api.github.com",
    "credential": "github_pat",
    "peer_ip":    "100.64.0.7",
    "http": {
      "method":  "POST",
      "path":    "/repos/...",
      "query":   { "per_page": ["100"] },
      "headers": { "Authorization": ["***"] },
      "body":    "..."
    }
  }
}
```

K8s and SQL fixtures swap the `http` block for a `k8s` or `sql`
block:

```json
{
  "match": { "endpoint": "k8s-dev", "rule": "no-secrets", "verdict": "deny" },
  "action": {
    "host": "10.0.0.7",
    "k8s": {
      "verb":      "get",
      "resource":  "secrets",
      "namespace": "default",
      "name":      "mysecret"
    }
  }
}
```

```json
{
  "match": { "endpoint": "pg-staging", "rule": "reads", "verdict": "allow" },
  "action": {
    "host": "pg-staging.internal:5432",
    "sql":  { "statement": "SELECT id FROM workflows WHERE id = 1" }
  }
}
```

### `match`

- `verdict` — required. One of `allow`, `deny`, `approve`,
  `passthrough`. `passthrough` parses but the runner won't replay
  it; pin to a terminal verdict or drop the fixture.
- `rule` — name of the rule that fired. Empty when no rule matched
  and the endpoint default was used.
- `endpoint` — optional. When set, pins dispatch (useful when
  multiple endpoints share a host, e.g. two integrations both
  hitting `api.anthropic.com`) and asserts the matched endpoint
  on replay.
- `reason` — informational only; the runner doesn't compare it.

`approve` is terminal: a rule routing to an approver chain records
`match.verdict = "approve"`. The human's eventual allow/deny is out
of scope for replay.

### `action`

- `host` — the host the agent dialed. Used by the loader for
  endpoint resolution when `match.endpoint` is absent. Required
  for SQL (no URL at the wire level); for HTTPS/k8s, redundant
  with the facet block's path but kept here so the facet block
  matches its CEL vocabulary exactly.
- `credential`, `peer_ip` — optional, mirror the gateway's
  request-level scalars.
- Exactly one facet block — `http`, `k8s`, or `sql`. Only that
  facet's CEL-visible fields go inside.

### Facet vocabulary

| Block | Fields |
|-------|--------|
| `http` | `method`, `path`, `query`, `headers`, `body`, `body_b64` |
| `k8s`  | `verb`, `resource`, `namespace`, `name`, `params` |
| `sql`  | `statement` (required); `verb`, `tables`, `function` (optional, derived from `statement` if omitted) |

Every field is optional except SQL's `statement`. Missing fields
default to zero values — rules that match on them just return
false. Fixtures that include the full struct (e.g. SQL with
explicit `verb` / `tables`) are accepted; explicit values take
precedence over derivation.

### Conventions

- `body` is raw UTF-8; `body_b64` is base64. Mutually exclusive.
- Headers and query maps are `map<string, list<string>>` so the
  format matches Go's `http.Header` and `url.Values`.
- Unknown keys anywhere in the file are load errors. This is
  intentional — typos in fixtures should fail loudly.

### Redaction

The exporter reads from the dashboard's SQLite store. Whatever
redaction the recording sink applied is what the fixture carries.

- **Headers are redacted.** Values of `Authorization`, `Cookie`,
  `X-Api-Key`, and similar sensitive headers are replaced with
  `"***"` before being persisted, so they ship that way in
  fixtures too.
- **Bodies are not redacted.** For well-behaved agents the body
  is what the agent sent — typically a placeholder like
  `{{github_pat}}`. For agents that inline secrets, the secret
  is what gets recorded. Review fixture files before committing
  them.
