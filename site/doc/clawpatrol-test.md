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

## A minimal end-to-end example

Drop these two files in a directory:

**`github.hcl`** — a tiny policy that allows GitHub reads and
denies writes:

```hcl
admin_email = "you@example.com"

credential "bearer_token" "github_pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = github_pat
}

rule "github-reads" {
  endpoint  = github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = github
  condition = "http.method in ['POST', 'PATCH', 'PUT', 'DELETE']"
  verdict   = "deny"
  reason    = "writes go through PR review"
}

profile "default" { endpoints = [github] }
```

**`fixtures/get-user.json`** — assert that `GET /user` is allowed:

```json
{
  "action": {
    "host": "api.github.com",
    "http": {
      "method":  "GET",
      "path":    "/user",
      "headers": { "Authorization": ["***"] }
    }
  },
  "match": {
    "verdict":  "allow",
    "rule":     "github-reads",
    "endpoint": "github"
  }
}
```

Run it:

```
$ clawpatrol test github.hcl fixtures/
ok   fixtures/get-user.json
1 action(s) checked, 0 mismatch(es)
```

Now break it. Edit `github.hcl` and flip `github-reads`' verdict
from `"allow"` to `"deny"`. Re-run:

```
$ clawpatrol test github.hcl fixtures/
FAIL fixtures/get-user.json
  want verdict="allow"      rule="github-reads"                 endpoint="github"
  got  verdict="deny"       rule="github-reads"                 endpoint="github"
1 action(s) checked, 1 mismatch(es)
$ echo $?
1
```

That's the whole loop.

## Workflow

Authoring fixtures by hand is fine for the smoke-test corpus above,
but in practice you record them from real traffic:

1. **Run a gateway locally** against the policy you want to
   regression-test:

   ```bash
   clawpatrol gateway -config github.hcl
   ```

2. **Send real requests through it.** Mix verdicts — drive the
   `allow` rules, drive the `deny` rules, drive any approver
   chains — so the corpus covers every comparison branch you care
   about.

   ```bash
   curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
   curl -X DELETE -H "Authorization: Bearer $GITHUB_TOKEN" \
     https://api.github.com/repos/me/sandbox/issues/1
   ```

3. **Click "Download action"** on each row's detail page in the
   dashboard. The browser saves a single `.json` file per action,
   already in the right format.

4. **Drop the files into a fixtures directory** and check them
   into your repo:

   ```
   .
   ├── github.hcl
   └── fixtures/
       ├── get-user.json
       └── delete-issue.json
   ```

5. **Run `clawpatrol test`** and expect `0 mismatches`.

6. **Make a policy change** and re-run. If a verdict moved, the
   runner prints the affected fixture and the `want` / `got` diff
   (like the example above).

The same fixtures become CI's regression set on every push.

### CI integration

The simplest possible GitHub Actions step:

```yaml
- name: Policy regression tests
  run: |
    curl -fsSL https://clawpatrol.dev/install.sh | sh
    clawpatrol test github.hcl fixtures/
```

The exit code does the work — non-zero fails the job and the diff
shows up in the log.

## Fixture format

Each fixture has two top-level keys: `action` is the recorded
request (what the agent did); `match` is the assertion (what the
rule engine should produce for that action). Exactly one facet
block (`http` / `k8s` / `sql`) lives under `action`, carrying that
facet's vocabulary — the same fields your CEL rule conditions read.

### HTTPS

```json
{
  "action": {
    "host":       "api.github.com",
    "credential": "github_pat",
    "peer_ip":    "100.64.0.7",
    "http": {
      "method":  "DELETE",
      "path":    "/repos/me/sandbox/issues/1",
      "headers": { "Authorization": ["***"] }
    }
  },
  "match": {
    "verdict":  "deny",
    "rule":     "github-writes",
    "endpoint": "github",
    "reason":   "writes go through PR review"
  }
}
```

### Kubernetes

```json
{
  "action": {
    "host": "10.0.0.7",
    "k8s": {
      "verb":      "get",
      "resource":  "secrets",
      "namespace": "default",
      "name":      "ci-deploy-key"
    }
  },
  "match": {
    "verdict":  "deny",
    "rule":     "no-secrets",
    "endpoint": "k8s-dev"
  }
}
```

### SQL

```json
{
  "action": {
    "host": "pg-staging.internal:5432",
    "sql":  { "statement": "SELECT id, name FROM workflows WHERE id = 1" }
  },
  "match": {
    "verdict":  "allow",
    "rule":     "pg-reads",
    "endpoint": "pg-staging"
  }
}
```

For SQL, only `statement` is required — the runner derives `verb`,
`tables`, and `function` from the SQL the same way the live
dispatch path does. You can override them by adding explicit fields
if you want to test the matcher's view directly.

### Shared hosts: pinning the endpoint

If two endpoints both claim the same host — common with
`api.anthropic.com`, where you might route Claude Code and a custom
agent through different rule sets — set `match.endpoint` explicitly:

```json
{
  "action": {
    "host": "api.anthropic.com",
    "http": { "method": "POST", "path": "/v1/messages" }
  },
  "match": {
    "verdict":  "approve",
    "rule":     "anthropic-default",
    "endpoint": "anthropic-agent-A"
  }
}
```

Without `match.endpoint`, the runner sees an ambiguous host and
errors:

```
FAIL fixtures/anthropic.json: host "api.anthropic.com" is claimed
by multiple endpoints [anthropic-agent-A anthropic-agent-B]; set
`match.endpoint` to disambiguate
```

## Reference

### `match`

- `verdict` — required. One of `allow`, `deny`, `approve`,
  `passthrough`. `passthrough` parses but the runner won't replay
  it; pin to a terminal verdict or drop the fixture.
- `rule` — name of the rule that fired. Empty when no rule matched
  and the endpoint default was used.
- `endpoint` — optional. When set, pins dispatch and asserts the
  matched endpoint on replay (see "Shared hosts" above).
- `reason` — informational only; the runner doesn't compare it.

`approve` is terminal: a rule routing to an approver chain records
`match.verdict = "approve"`. The human's eventual allow/deny is out
of scope for replay.

### `action`

- `host` — the host the agent dialed. Used by the loader for
  endpoint resolution when `match.endpoint` is absent. Required
  for SQL (no URL at the wire level).
- `credential`, `peer_ip` — optional, mirror the gateway's
  request-level scalars.
- Exactly one facet block — `http`, `k8s`, or `sql`.

### Facet vocabulary

| Block | Fields |
|-------|--------|
| `http` | `method`, `path`, `query`, `headers`, `body`, `body_b64` |
| `k8s`  | `verb`, `resource`, `namespace`, `name`, `params` |
| `sql`  | `statement` (required); `verb`, `tables`, `function` (optional, derived from `statement` if omitted) |

Every field is optional except SQL's `statement`. Missing fields
default to zero values — rules that match on them just return
false. Fixtures that include the full struct are accepted;
explicit values take precedence over derivation.

### Conventions

- `body` is raw UTF-8; `body_b64` is base64. Mutually exclusive.
- Headers and query maps are `map<string, list<string>>` so the
  format matches Go's `http.Header` and `url.Values`.
- Unknown keys anywhere in the file are load errors. Typos in
  fixtures should fail loudly.

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
  is what gets recorded. **Review fixture files before committing
  them.**
