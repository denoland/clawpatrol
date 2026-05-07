# Config model

`gateway.hcl` is the source of truth for declarative policy. The
dashboard is a remote editor + observability surface, not a separate
config store. This document spells out the split so future contributors
don't accidentally invent a third layer.

## What lives in HCL

Declarative policy that an operator versions, reviews, and ships:

- `endpoint`, `credential`, `profile`, `policy`, `approver`, `rule`
  blocks — every typed plugin entity.
- `defaults {}` — fallback verdicts, llm cache TTLs, human timeouts.
- Operational fields — `listen`, `info_listen`, `public_url`,
  `admin_email`, `dashboard_secret`, `ca_dir`, `oauth_dir`, `log_path`,
  `tailscale {}`.

The file's structure, comments, and whitespace are operator-owned.
The dashboard editor preserves them — saving round-trips the bytes,
not a re-emit.

## What lives in SQLite

Runtime state that's minted, mutated, or refreshed during operation:

- `credentials` — OAuth token bytes (access, refresh, expiry) per
  `(integration_id, profile)`. Persisted by `oauthState.persist`.
- `credential_secrets` — non-OAuth slot values (API keys, mTLS bundles)
  per `(credential_id, profile, slot)`. Written by `apiCredentialsSet`.
- Onboard registry — peer IP claims, hostnames, profile assignments.
- HITL pending decisions, observed traffic, sessions, analytics rollups.

HCL declares *which* credentials and endpoints exist; SQLite stores
*the secrets and ephemeral state* that those declarations point at.

## Hot-reload

`watchConfig` (`main.go`) polls `gateway.hcl` mtime every 3s. On change
it re-parses and hot-swaps the policy graph: rules, endpoints,
profiles, credential plugins, the conn-IP index, dnsvip, and the
operational `*config.Gateway` (so dashboard secret changes apply
without a restart). What does *not* hot-reload: `listen`, `info_listen`,
`ca_dir`, `oauth_dir`, the `tailscale {}` block. Edit those, restart.

## How the dashboard mutates config

One write path: `PUT /api/config` (`web.go apiConfig`). It validates
the body via `config.LoadBytes`, writes atomically (temp file +
rename), and lets the mtime watcher pick it up. The dashboard surfaces
this through:

- **Pencil** on the rules panel → opens `gateway.hcl` in a textarea
  (`RulesEditor.tsx`).
- **Gear** in the device picker → same editor, scoped to global
  settings (`SettingsModal.tsx`).
- **AI helper** (`POST /api/rules/ai`, `web.go apiRulesAI`) — generates
  a proposed HCL diff from a natural-language prompt. The operator
  reviews the result in the textarea before clicking Save. The AI
  endpoint never writes to disk on its own.

There is no other dashboard → HCL write path. Per-device rule overrides
that the dashboard used to splice into the file have been removed —
the pencil now opens the whole file, period.

## Rule of thumb when adding features

Before persisting anything new, ask: *would the operator commit this
to git?*

- **Yes** → it's policy. Goes in HCL. Add a plugin / block kind, gate
  hot-reload appropriately, surface read-only views in the dashboard.
- **No** (it's secret bytes, an OAuth token, a runtime claim, an
  observation, a decision) → it's runtime state. Goes in SQLite.
  Migrations live in `migrations/sqlite/`.

Resist the third option ("dashboard writes a sidecar HCL file" /
"dashboard splices into `gateway.hcl`"). Both layers are already
sufficient; a third invents drift.
