# Credentials

Agents call upstream APIs that want secrets — a GitHub PAT, an
Anthropic key, a Postgres password. One of the things Claw Patrol
does, alongside the [rule engine](/docs/rules/) and the
[approver flow](/docs/glossary/#approver), is hold those secrets
on the gateway side and inject them at the wire so the agent
process never touches them. This page covers that piece: how the
agent ends up sending a request that looks authentic without ever
holding the real token, and how to configure the case where one
identity wields more than one credential at the same endpoint.

For the definitional one-liners see
[Glossary](/docs/glossary/#credential). For the field-by-field HCL
schema see [Config Reference](/docs/config-reference/). For *why*
this design defeats a hostile agent see
[Security Model](/docs/security-model/).

## The mental model

A credential has two parts that live in different places:

- A **`credential` block** in `gateway.hcl` — type, name, which
  endpoint it binds to, optional fields like `user` for Postgres.
  Declarative; checked into git.
- The **secret bytes** themselves — the PAT, the OAuth refresh
  token, the password. Live in the gateway's
  [secret store](/docs/glossary/#secret-store) (default: env vars
  keyed `CLAWPATROL_SECRET_<UPPER_NAME>`, with `@/path/to/file`
  shorthand for PEM bundles). Pasted via the dashboard for most
  operators. Never in HCL.

The agent never sees the second part. What it sees is a
**placeholder**: a string that looks like a real token (so the
agent's SDK accepts it at startup) but carries no upstream
authority. When the agent makes a request, the gateway terminates
TLS, finds the placeholder in the auth slot, swaps it for the real
secret bytes from the store, and forwards.

```
        gateway.hcl              secret store
       credential "github"      CLAWPATROL_SECRET_GITHUB
              │                          │
              └──────────┐    ┌──────────┘
                         ▼    ▼
   agent ──── PH ────► gateway ──── real secret ────► upstream
         (env var)              (MITM substitution)
```

## How the placeholder reaches the agent: env pushdown

The daemon writes per-credential env vars into the process
environment before exec. Built-in plugins know which env vars their
SDKs read; the daemon ships the placeholder as the value. For
example, the GitHub plugin contributes:

```
GH_TOKEN=ghp_clawpatrol_placeholder_do_not_use
GITHUB_TOKEN=ghp_clawpatrol_placeholder_do_not_use
```

`gh auth status`, the `octokit` SDK, GitHub Actions tooling — they
all read those env var names and find what looks like a valid
classic PAT. Anthropic, OpenAI, and Gemini ship similarly
shape-validated placeholders. The agent never sees a different code
path; from its point of view, the env contains a real token.

You can see the full set with:

```bash
clawpatrol env
```

`clawpatrol run <cmd>` exports those env vars into `<cmd>`'s
environment automatically. For long-lived shells, source them once
via your shell rc:

```bash
eval "$(clawpatrol env)"
```

Set `CLAWPATROL_NO_ENV=1` to disable pushdown for a single
invocation.

Generic credential types (`bearer_token`, `header_token`, `mtls`)
have no built-in pushdown — their SDKs don't have a published env
var convention. For those, either dial directly through the
gateway's network path (the credential still injects at MITM time)
or set the env var yourself.

## On the wire: substitution at MITM time

The gateway terminates TLS, parses the request, and runs the
credential plugin's `InjectHTTP` (or `InjectSQL`, etc). For a
bearer token, injection is one line: rewrite the `Authorization`
header to `Bearer <real secret bytes>`. For Postgres it's the
StartupMessage `user` and the password handshake. For mTLS, the
upstream-side TLS client cert and key. The placeholder bytes never
leave the gateway.

This means the agent's request as it leaves the device looks
authentic enough to satisfy SDK validation but is harmless if
intercepted — the placeholder doesn't authenticate against the
upstream.

## Single credential (the common case)

One credential per (profile, endpoint). No placeholder string in
HCL — the built-in is enough:

```hcl
endpoint "https" "github" { hosts = ["api.github.com"] }

credential "github_oauth" "github" {
  endpoint = https.github
}

profile "default" {
  credentials = [github_oauth.github]
}
```

The agent under this profile gets
`GITHUB_TOKEN=ghp_clawpatrol_placeholder_do_not_use` pushed into its
env, calls `api.github.com` through the tunnel, and the gateway
swaps in the real PAT. Most credentials live here.

## Two credentials at one endpoint: placeholder dispatch

When a profile wields **two credentials of the same family at the
same endpoint** — for example, both a prod and a staging GitHub PAT
in one profile — the built-in placeholder no longer disambiguates.
Two credentials, one `Authorization: Bearer …` slot, one wire: the
gateway can't tell which token to substitute.

Resolution: assign your own placeholder strings in the profile, one
per credential.

```hcl
endpoint "https" "github" { hosts = ["api.github.com"] }

credential "bearer_token" "github-prod"    { endpoint = https.github }
credential "bearer_token" "github-staging" { endpoint = https.github }

profile "ci" {
  credentials = [
    { placeholder = "PH_gh_prod",    credential = bearer_token.github-prod },
    { placeholder = "PH_gh_staging", credential = bearer_token.github-staging },
  ]
}
```

At request time the gateway scans the auth slot for one of those
placeholders and substitutes the matching credential's real bytes.
A bare-name entry in the same list (no inline object) is the
**fallback** for that (profile, endpoint) pair — used when the
agent sends nothing matching a placeholder. At most one fallback
per (profile, endpoint).

### Getting the placeholder into the agent's env

The daemon's env pushdown is per-plugin, not per-credential — it
exports one value per env var, not a value per (env var,
credential) pair. So for placeholder dispatch you set the env var
manually before launching the workflow that should use that
credential:

```bash
GITHUB_TOKEN=PH_gh_prod    clawpatrol run ./prod-job
GITHUB_TOKEN=PH_gh_staging clawpatrol run ./staging-job
```

The agent reads `GITHUB_TOKEN` normally; the gateway sees
`PH_gh_prod` in the wire and picks `github-prod`. No SDK changes,
no agent awareness.

### When you don't need placeholder dispatch

You only need it when **the same profile** actively wields two
credentials at one endpoint. Two GitHub credentials defined
globally but split across two profiles (one each) need no
placeholders — each profile's resolution is already unambiguous.
The example config under `examples/gateway.example.hcl` has
`anthropic_oauth_subscription` and `anthropic_manual_key` both
bound to the `anthropic` endpoint, but they live in disjoint
profiles, so there's no dispatch problem.

## Where the real secret lives

The gateway resolves a credential's secret bytes through three
backends, in this order:

1. **Dashboard** — values pasted into the credential's slot(s) in
   the operator UI, persisted in the gateway's sqlite store. This
   is the path most operators use.
2. **OAuth registry** — for OAuth-flow credentials (Claude,
   Codex, GitHub OAuth, Notion, …) the gateway runs the device
   flow at first dashboard visit, then refreshes tokens
   automatically.
3. **Env vars on the gateway host** —
   `CLAWPATROL_SECRET_<UPPER_NAME>`, with hyphens normalized to
   underscores. A credential named `github-prod` falls back to
   `CLAWPATROL_SECRET_GITHUB_PROD`. Used as a last-resort
   fallback for ops-by-deploy / systemd / Kubernetes workflows.

For multi-slot credentials (mTLS in particular), each slot is its
own env-var key under the credential's base name —
`CLAWPATROL_SECRET_<NAME>_CERT`, `_KEY`, `_CA`. Single-slot
credentials (`bearer_token`, `postgres_credential`, …) use the
bare key.

Env-var values starting with `@` are read as a file path — keeps
PEM bundles out of the env table:

```bash
export CLAWPATROL_SECRET_K8S_PROD_CERT=@/etc/clawpatrol/k8s-prod.crt
export CLAWPATROL_SECRET_K8S_PROD_KEY=@/etc/clawpatrol/k8s-prod.key
```

Dashboard-pasted values win over env vars when both exist — once
an operator commits a value through the UI, the gateway treats it
as the source of truth and stops consulting env fallbacks for that
credential. Precedence is per-credential, not per-slot: once any
slot is set via the dashboard, the gateway treats the dashboard as
the source of truth for **all** slots of that credential and
ignores env fallbacks even for slots you didn't paste. So for
multi-slot credentials like mTLS, paste every required slot through
the same channel — mixing dashboard for `cert` and env for `key`
will silently fall through to an empty key.

## Matching on credential in rules

Rules can scope by which credential the gateway selected. The
`credential = X` predicate on a rule is the dispatch hook back into
policy: only that rule arm runs when the gateway resolved to `X`.
The canonical use is gating writes:

```hcl
credential "postgres_credential" "pg-readonly" {
  endpoint = postgres.pg
  user     = "agent_ro"
}
credential "postgres_credential" "pg-writer" {
  endpoint = postgres.pg
  user     = "agent_rw"
}

rule "pg-writes" {
  endpoint   = postgres.pg
  credential = postgres_credential.pg-writer
  condition  = "sql.verb in ['insert', 'update', 'delete', 'merge']"
  approve    = [human_approver.support-ops]
}
```

Postgres dispatches on the StartupMessage `user`, so the gateway
already knows which credential is in play before any SQL parses —
the rule's `credential = pg-writer` clause is what tells policy "I
only apply when the writer is the one talking."

## What's next

- The full HCL field list lives in
  [Config Reference › credential](/docs/config-reference/#credential).
- For the broader request flow (where credential injection sits
  relative to TLS termination, rule matching, and the audit log)
  see [Architecture](/docs/architecture/).
- For the threat model — why a hostile agent can't extract the
  real credential, swap its placeholder for another credential's,
  or coerce the gateway into leaking the real secret — see
  [Security Model](/docs/security-model/).
