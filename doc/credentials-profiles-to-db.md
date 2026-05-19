# Credentials and profiles to the database (design proposal)

**Design principle.** Adding a new agent should not require editing HCL.

Today every personnel change (new team member, new bot, granting an
existing user access to one more service) ends with a git commit and a
gateway restart. That makes the file a record of every Slack handle on
the team, scales config noise with headcount instead of policy
complexity, and locks personnel changes behind code review even though
nothing about the policy itself is changing.

The proposal: keep rules, approvers, endpoints, and gateway operational
config in HCL; move credentials and profiles to the database, edited
through the dashboard. Rules and infrastructure (the things worth
reviewing) stay code-reviewed. Personnel (the things that change every
week) become dashboard operations.

## TL;DR

- HCL keeps: rules, approvers, endpoints, tunnels, plugin loads, the
  gateway's listen/state/transport config.
- DB owns: credentials (declaration + per-slot secret), profiles
  (assignments of identity to endpoint+credential pairs).
- Profile schema changes: today a profile lists endpoints, and each
  endpoint carries a credential. After this change a profile lists
  `(endpoint, credential)` pairs, and an endpoint no longer carries a
  credential at all.
- That schema change collapses the per-person endpoint duplication in
  `deno.hcl` (one `anthropic` endpoint instead of N copies, one
  `github` instead of M copies).
- Dashboard grows two pages: credentials (add/edit/delete) and profiles
  (assign endpoints+credentials to an identity).
- Migration: first boot reads existing `credential`/`profile` blocks
  from HCL and seeds the DB. Subsequent operator edits override.

## Why now

The friction is concrete. Sample sequence for "Bartek joins the team
and needs ClickHouse read access":

1. Edit `~/src/clawpatrol-deno/deno.hcl`. Add a `credential
   "clickhouse_credential" "ch-bartek-cred"` block. Add an `endpoint
   "clickhouse_native" "clickhouse-bartek"` block bound to that
   credential. Add `clickhouse-bartek` to `profile "bartek"`.
2. `git commit && git push`.
3. SSH to clawpatrol-gateway, `git pull`, `systemctl restart clawpatrol-gateway`.
4. Bartek logs into the dashboard and pastes the ClickHouse password
   into the credential secret store.

Step 4 already lives in the dashboard. Steps 1-3 are pure ceremony for
"give Bartek access" - nothing about the rule engine or the cluster's
TLS config has changed.

Look at `deno.hcl` itself. The first 200 lines are mostly:

```hcl
credential "anthropic_oauth_subscription" "anthropic_subscription_divy"    {}
credential "anthropic_oauth_subscription" "anthropic_subscription_arnau"   {}
credential "anthropic_oauth_subscription" "anthropic_subscription_bartek"  {}
credential "anthropic_oauth_subscription" "anthropic_subscription_nathan"  {}

endpoint "https" "anthropic-divy"   { hosts = ["api.anthropic.com"]; credential = anthropic_subscription_divy   }
endpoint "https" "anthropic-arnau"  { hosts = ["api.anthropic.com"]; credential = anthropic_subscription_arnau  }
endpoint "https" "anthropic-bartek" { hosts = ["api.anthropic.com"]; credential = anthropic_subscription_bartek }
endpoint "https" "anthropic-nathan" { hosts = ["api.anthropic.com"]; credential = anthropic_subscription_nathan }
```

Four copies of one endpoint, distinguished only by which credential
they bind. That duplication exists because the current schema forces
exactly one credential per endpoint. It is the obvious smell.

## Current state

Today's split between HCL and DB:

| Concept              | Declaration | Secret value | Why                              |
|----------------------|-------------|--------------|----------------------------------|
| Rules                | HCL         | n/a          | Policy. Code-reviewed.           |
| Approvers            | HCL         | n/a          | Policy. Code-reviewed.           |
| Endpoints            | HCL         | n/a          | Infra (host, TLS, region).       |
| Tunnels              | HCL         | n/a          | Infra.                           |
| Credentials          | HCL         | DB           | **Mixed. The smell.**            |
| Profiles             | HCL         | n/a          | Personnel.                       |
| Sessions, action log | n/a         | DB           | Runtime state.                   |

Credentials are already half-DB-backed: the secret values
(`credential_secrets` table, see migration 0011) are dashboard-edited,
but the declarations (kind, name, structural fields like `user`,
`cookie_name`) sit in HCL. Adding a new credential is therefore an
HCL edit plus a dashboard paste. Half-and-half is the worst of both:
you commit, push, and SSH for the structural half, and dashboard-edit
the secret half.

Profiles are fully HCL. Adding an endpoint to a profile is an HCL
edit. Removing one is too.

## Proposal

**HCL.** Rules, approvers, endpoints (host/protocol/TLS), tunnels,
plugin loads. Endpoints lose the `credential` field. Tunnels lose the
`credential` field. Everything else as today.

**DB.** Credentials (kind + name + per-slot secret), profiles
(identity + endpoint+credential pairs). Both fully dashboard-editable.

New tables (additive to the existing `credential_secrets`):

```sql
CREATE TABLE credentials (
    name       TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,        -- e.g. "anthropic_oauth_subscription"
    fields     TEXT NOT NULL,        -- JSON blob, per-kind structural fields
    created_ns INTEGER NOT NULL,
    updated_ns INTEGER NOT NULL
);

CREATE TABLE profiles (
    name       TEXT PRIMARY KEY,
    created_ns INTEGER NOT NULL,
    updated_ns INTEGER NOT NULL
);

CREATE TABLE profile_endpoints (
    profile    TEXT NOT NULL,        -- FK profiles.name
    endpoint   TEXT NOT NULL,        -- name of an endpoint declared in HCL
    credential TEXT,                 -- FK credentials.name, NULL for unauth'd
    PRIMARY KEY (profile, endpoint),
    FOREIGN KEY (profile)    REFERENCES profiles(name)    ON DELETE CASCADE,
    FOREIGN KEY (credential) REFERENCES credentials(name) ON DELETE RESTRICT
);
```

`credential_secrets` already keys by `(credential, slot)`, so the
existing dashboard plumbing for secret entry stays unchanged.

After this, `deno.hcl`'s anthropic block becomes:

```hcl
endpoint "https" "anthropic" {
  hosts = ["api.anthropic.com"]
}
```

One declaration. The "Divy's Anthropic subscription" / "Arnau's
Anthropic subscription" knowledge moves to the `profile_endpoints`
rows, which look like:

```
profile=divy   endpoint=anthropic   credential=anthropic_subscription_divy
profile=arnau  endpoint=anthropic   credential=anthropic_subscription_arnau
profile=bartek endpoint=anthropic   credential=anthropic_subscription_bartek
```

The credential rows themselves carry the kind:

```
name=anthropic_subscription_divy   kind=anthropic_oauth_subscription
name=anthropic_subscription_arnau  kind=anthropic_oauth_subscription
```

## Loader changes

`internal/config/Load()` currently parses HCL into a single `Policy`
struct. After this change it parses HCL into a partial policy
(endpoints, rules, approvers, tunnels) and then reads `credentials`,
`profiles`, and `profile_endpoints` from the DB to fill in the rest.
The runtime `Policy` type stays the same shape; only the population
step changes.

Hot reload extends to DB writes: dashboard CRUD on credentials or
profiles triggers `Policy` rebuild via the same path that HCL file
changes use today. The file watcher and the DB-write hook share an
implementation.

## Dashboard surface

Two new pages plus reuse of the existing secret-store form.

**Credentials.** List of rows. "New credential" form picks a kind
from the plugin registry (the gateway already enumerates these),
takes a name and the per-kind structural fields, and writes the row.
The existing "paste the secret" UI gets reused unchanged; the
credential row's `kind` decides which slots the form prompts for.

**Profiles.** List of profile names. "New profile" creates a row.
Profile detail page shows endpoints (drawn from HCL) with a column
per endpoint for "credential to use" (dropdown of compatible
credentials). Save writes to `profile_endpoints`.

Validation is check-on-write: kind must exist in the plugin registry;
credential kind must be compatible with the endpoint's expected
credential interface (the plugin SDK already exposes this).

## Migration

First-boot heuristic, run inside the migration after the new tables
exist: scan the HCL `policy.Credentials` and `policy.Profiles` and
seed the DB tables with their contents. The seed is idempotent so
operators can roll back the gateway binary without losing data and
roll forward without re-seeding.

After the first boot, the HCL `credential` and `profile` blocks are
either:

- Treated as ignored (DB wins, HCL warns once on parse), or
- Hard-rejected (HCL parse error: "credential blocks are no longer
  valid; manage credentials via the dashboard").

The first option keeps existing deployments running without an HCL
edit. Switching to the second is a follow-up once everyone has
migrated.

`clawpatrol validate file.hcl` keeps working - it validates the HCL
half (rules, endpoints, approvers). DB-backed config is checked at
runtime against the loaded plugin registry.

## What this costs

**Loss of git-tracked history for personnel.** Today
`git blame deno.hcl` shows when a credential was added and why. After
this change the audit trail lives in the dashboard's action log per
gateway instance. Real loss for forensics in a team setting; arguably
worth tagging admin operations with the dashboard operator's whois
identity so the audit log is at least attributable.

**Multi-environment story gets harder.** Today, copying `prod.hcl`
to `staging.hcl` and editing a few addresses gives you a working
staging gateway. With DB-backed credentials and profiles, staging
starts empty and operators re-enter the personnel state by hand.
Mitigation: `clawpatrol gateway dump-profiles` / `dump-credentials`
subcommands that emit a portable JSON snapshot, plus a matching
`restore` path. The HCL stays human-edited, the DB tables get a
machine-edited export format.

**Two sources of truth during migration.** While both HCL and DB
declarations are accepted, operators may forget where they wrote
something. The migration shortens this window by seeding the DB on
first boot, but the awkward period is real until the HCL blocks are
rejected outright.

## Open questions

- Should `profile_endpoints.credential` be nullable, or is "an
  endpoint with no credential" always an error? Today some HTTPS
  endpoints intentionally have no credential (the gateway passes the
  request through unmodified, just for the rule engine to see it).
  Lean toward nullable.

- Identity binding. Profiles in HCL today are named (`profile
  "divy"`) and the runtime picks the profile from the agent's IP via
  `agentIPFor()`. With DB profiles, the binding stays the same but
  the dashboard could surface "which agents are using this profile"
  as a join against the device table. Out of scope for the initial
  cut.

- Plugin schema. Credentials of kind `clickhouse_credential` carry a
  `user` field; `mtls_credential` carries no fields; `cookie_token`
  carries `cookie_name`. The dashboard form needs to render these
  per kind. Either reflect from the Go struct at runtime (existing
  approach), or make plugins emit a JSON Schema describing their
  fields (cleaner long-term, more work now).

## Sequencing

The full change is large enough to want phasing:

1. **Profiles to DB, schema unchanged.** Move `profile` blocks to a
   `profiles(name, endpoints_csv)` table. Endpoint+credential coupling
   stays in HCL via the endpoint's `credential` field. This is the
   smallest win that removes the friction for "give Bartek access to
   an existing endpoint." A week of work, minimal new dashboard UI.

2. **Credentials to DB.** Add the `credentials` table; loader merges
   DB rows on top of HCL declarations; dashboard gets a credentials
   page. HCL credential blocks become legacy-only, still accepted.

3. **Schema change to `profile_endpoints`.** Now that both sides
   live in the DB, change the profile schema so it carries
   `(endpoint, credential)` pairs and the endpoint declarations lose
   their `credential` field. This is when the per-person endpoint
   duplication in `deno.hcl` collapses.

4. **Reject HCL credential/profile blocks.** Once every deployment
   has migrated, the HCL parser rejects them with a pointer to the
   dashboard. The HCL surface shrinks to rules, approvers, endpoints,
   tunnels, plugins, and gateway operational config.

Each phase is independently shippable and reverts cleanly.

## Out of scope

- Multi-tenant authorization in the dashboard (who can edit whose
  profile). Today the dashboard is single-operator-with-password;
  this proposal does not change that. A multi-tenant dashboard is
  its own design and would build on whatever lands here.

- Endpoint declarations moving to DB. Endpoints carry real
  infrastructure decisions (CA pins, hostnames, TLS settings). Those
  belong in code review. Future work could revisit, but the friction
  this proposal targets is personnel, not infrastructure.

- Renaming things. "Profile" has accumulated meaning across versions
  of the config. A cleaner name (identity? actor? role?) is worth
  bikeshedding separately.
