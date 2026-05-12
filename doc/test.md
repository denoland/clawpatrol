# `clawpatrol test`

A CLI that replays recorded gateway actions against a candidate HCL
policy and reports any verdict drift. Pure CLI — no gateway, no DB,
no auth.

```
clawpatrol test <config.hcl> <fixture.json | fixture-dir>
```

Exit 0 when every fixture matches; 1 on any mismatch or fixture
load error; 2 on usage / config-load error.

## Fixture format

Two top-level keys: `match` is the assertion (what the rule engine
should produce); `action` is the recorded request (what the agent
did). Every fixture has exactly one facet block under `action`
(`http` / `k8s` / `sql`) carrying that facet's CEL vocabulary.
Connection-level fields (`host`, `credential`, `peer_ip`) live on
`action` itself.

```json
// HTTPS
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

// K8s
{
  "match": { "endpoint": "k8s-dev-ams", "rule": "k8s-no-secrets", "verdict": "deny" },
  "action": {
    "host": "209.250.247.66",
    "k8s": {
      "verb":      "get",
      "resource":  "secrets",
      "namespace": "default",
      "name":      "mysecret"
    }
  }
}

// SQL
{
  "match": { "endpoint": "pg-deploy-classic-staging", "rule": "pg-staging-reads", "verdict": "allow" },
  "action": {
    "host": "main-pg14.denosr-staging.internal:5432",
    "sql": {
      "statement": "SELECT id, name FROM workflows WHERE id = 1"
    }
  }
}
```

### `match`

What the rule engine produced (or what the runner should assert).

- `verdict` — one of `allow`, `deny`, `approve`, `passthrough`.
  Required. `passthrough` parses but the runner rejects it at
  replay (no upstream to dial, no policy to assert) — drop or
  re-pin to a terminal verdict before checking the fixture in.
- `rule` — name of the matched `CompiledRule`. Empty when no rule
  fired and the endpoint default was used.
- `endpoint` — optional. When set, pins dispatch (under hosts
  shared by multiple endpoints, e.g. `api.anthropic.com` in deno.hcl)
  and asserts the matched endpoint on replay.
- `reason` — informational; not compared by the runner.

### `action`

The recorded request. Connection-level fields plus one facet block.

- `host` — the host the agent dialed. Used by the loader for
  endpoint resolution when `match.endpoint` is absent. For SQL,
  required (no URL at wire level). For HTTPS/k8s, redundant with
  the family block's path but extracted out to keep the facet
  block aligned with its CEL vocabulary.
- `credential`, `peer_ip` — `match.Request` scalars; optional.
- Exactly one facet block: `http`, `k8s`, or `sql`. The block name
  matches `Facet.Name()`. Block content is **only** the facet's
  CEL-visible fields (the vocabulary rules read via
  `<facet>.<field>` in their `condition`).

### Facet blocks

| Block | CEL vocabulary |
|-------|----------------|
| `http` | `method`, `path`, `query`, `headers`, `body`, `body_b64` |
| `k8s` | `verb`, `resource`, `namespace`, `name`, `params` |
| `sql` | `statement` (required); `verb`, `tables`, `function` (optional, derived from `statement` by the endpoint's `runtime.SQLParser` if omitted) |

Every field inside a facet block is optional except SQL's
`statement`. Missing fields default to zero values — rules that
match on them just return false. Fixtures that include the full
struct (e.g. SQL with explicit verb/tables/function) are accepted;
explicit values take precedence over derivation.

`approve` is terminal — the runner doesn't invoke the approver
chain. A rule routing to an approver records
`match.verdict = "approve"`; the human's eventual allow/deny is
out of scope.

### Conventions

- `body` is raw UTF-8; `body_b64` is base64. Mutually exclusive.
- Headers and query maps are `map<string, list<string>>` to match
  `http.Header` and `url.Values`.
- Unknown keys anywhere in the file are load errors.

### Redaction

The exporter reads from the `actions` SQLite table. Whatever
redaction the sink applied at write time is what the fixture
carries.

- Headers: redacted. `flatHeaders` replaces values of
  `Authorization`, `Cookie`, `X-Api-Key`, etc. with `"***"` before
  the headers JSON hits SQLite.
- Bodies: not redacted. For well-behaved agents the body is what
  the agent sent (a placeholder like `{{github_pat}}`); for agents
  that inline secrets, it's the secret. Review fixture files
  before checking them in.

## Local workflow

1. **Start a local gateway** with a small config pointing at a
   real upstream (e.g. `clawpatrol gateway -config test.hcl`).
2. **Send real requests** through it. Mix verdicts —
   `allow` / `deny` / `approve` — so the corpus covers every
   comparison branch.
3. **Click "Download action"** on each row's detail page. The
   browser saves a single `.json` file per action.
4. **Drop the files into `fixtures/`** and check them into the
   repo.
5. **Run `clawpatrol test test.hcl fixtures/`**. Expect exit 0
   with `N actions checked, 0 mismatches`.
6. **Mutate the config** — flip an `allow` to `deny`, rename a
   rule — and re-run. Expect non-zero exit and a printed diff
   naming the affected fixture files.

The same fixtures become CI's regression set on every push.
