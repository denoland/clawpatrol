# RFC: `clawpatrol apply`

Status: **V1 (local) implemented; remote apply proposed.**
Author: config-workflow track
Related: R&D standup 2026-06-01 (config editing + `cloudpatrol apply`),
[doc/roles.md](roles.md) (RBAC, the auth basis for remote apply).

## Problem

The gateway config is read-only-from-file. To change a deployed
gateway today you:

1. edit `gateway.hcl` locally (or in a config repo),
2. `scp` it to the box (`scp gateway.hcl root@deno.clawpatrol.dev:/opt/clawall/`),
3. restart or let the 3-second file watcher pick it up,
4. hope it parses — an invalid config that reaches the watcher can break
   a running gateway with no gate in front of it.

There is **no record** of what changed, who changed it, or when; no diff
before the change goes live; no way to see the sequence of configs a
gateway has run; and no rollback. The "push from CI" story is just
`scp` in a CI runner with an SSH key.

The standup framed the fix as a Terraform-`apply`-like workflow: textual
HCL stays the source of truth, but changes go through a validated,
diffed, audited, reversible command.

## Goals

- **Validate before activate.** An invalid config never reaches a
  running gateway.
- **Diff before activate.** Show what actually changes, semantically.
- **Audit.** Every applied config is recorded: bytes, who, when, why.
- **Reversible.** History is queryable; rollback is "apply an old
  version".
- **Eventually: kill `scp`.** A `clawpatrol apply --remote` that pushes
  to a running gateway over its existing authenticated API, so neither
  an SSH key nor filesystem access to the box is needed.

## Non-goals (for now)

- A config *editor* in the dashboard (separate track; this is the
  plumbing it would sit on).
- Multi-gateway fan-out / fleet orchestration.
- Secret material in the version store (secrets live in the DB secret
  store, never in HCL — unchanged).

## Design

### Config version store — implemented

`migrations/sqlite/0020_config_versions.sql`:

```
config_versions(id, revision, schema_version, content, applied_by, note, applied_ns)
```

- `content` is the **exact operator bytes** — comments preserved. We
  store the file, not an `Emit()` round-trip, so the audit trail is
  byte-faithful.
- `revision` is `SHA-256(content)`, matching the dashboard's existing
  `X-Config-Revision` header so the CLI and dashboard agree on identity.
- A row is inserted only when the revision differs from the latest, so
  boot + apply + reload of the same config don't pile up duplicates
  (`recordConfigVersion`).

The gateway records the config it loads **at boot**
(`recordBootConfigVersion`), so history starts from the
currently-running config rather than from the first `apply`.

### Semantic diff — implemented

`config.PolicyDigest(gw)` renders every operational and policy block to
its own canonical HCL string via the existing deterministic `Emit`
hooks, keyed by a human label (`gateway`, `endpoint anthropic`,
`profile avocet2`, …). `diffDigests` compares two digests by key →
added / removed / changed. Because each block is canonicalized,
reordering blocks or editing a comment shows as **no change** — only a
real content change to a block registers. This is the "semantic, not
textual" diff the standup asked for, without a full field-level
differ.

### `clawpatrol apply <config.hcl>` — implemented (local)

Runs **on the gateway host**:

1. load + compile + external-plugin verify (same pipeline as daemon
   startup) — reject invalid configs here, before they can go live;
2. open the gateway's DB (resolved from the config's `state_dir`);
3. semantic-diff against the last applied version, print it;
4. confirm (`-y` to skip; `--by`, `--note` for the audit row);
5. rewrite the file **atomically** (temp + rename, mode preserved) so
   the watcher never sees a half-written file and the mtime bump
   triggers reload;
6. record a `config_versions` row.

`clawpatrol config history <config.hcl>` lists recorded versions
(newest first, with revision, schema version, who, when, note).

### Drift & conflict — partially proposed

- **Drift** (file changed out-of-band vs last applied): boot-recording
  already captures out-of-band edits into history. `apply` could warn
  "the on-disk config differs from the last applied revision" before
  proceeding. *Not yet wired.*
- **Conflict / optimistic lock** for CI: `apply --expect <revision>`
  fails if the latest recorded revision isn't `<revision>`, so two CI
  jobs can't silently clobber each other. *Proposed.*

### Remote apply — proposed (this is the `scp` killer)

> **Direct answer to "does this solve the remote / scp problem?": not
> the V1 above — this section does.**

V1 still runs on the box. To remove `scp` and read-only-file pushes
entirely, add `clawpatrol apply --remote <gateway-url> config.hcl`:

1. CLI validates + compiles locally (fail fast, no round-trip);
2. CLI POSTs the config bytes to a new authenticated gateway endpoint
   `POST /api/config` with `If-Match: <expected-revision>`;
3. the gateway re-validates, computes the diff, applies in-process
   (atomic write to its own config path **or** direct in-memory swap),
   records the `config_versions` row with `applied_by` = the caller's
   RBAC identity, and returns the new revision;
4. `412 Precondition Failed` on revision mismatch (the optimistic lock).

This reuses machinery that already exists:

- **Auth**: the dashboard API gate + [RBAC roles](roles.md). Applying
  config is an `admin`/global-`editor` action — `POST /api/config` slots
  into the same `authzGate` as every other write. CI gets a scoped
  identity instead of a root SSH key.
- **Transport**: the gateway is already reachable over Tailscale /
  WireGuard / its public URL. No new listener.
- **Storage + diff + audit**: identical to V1; only the *trigger* moves
  from local CLI to an authenticated request.

Result: editing config from a laptop or CI becomes
`clawpatrol apply --remote` — authenticated by role, validated before it
lands, diffed, audited, and reversible. No SSH key on the box, no
filesystem write, no read-only-file dance.

### Rollback — proposed

`clawpatrol config rollback <config.hcl> --to <revision>` writes the
stored `content` of an earlier version back through the same apply path
(local or remote). The bytes are already in `config_versions`.

## Implementation status

| Piece                                  | Status        |
| -------------------------------------- | ------------- |
| `config_versions` table + DB layer     | ✅ implemented |
| Boot-time version recording            | ✅ implemented |
| `config.PolicyDigest` semantic diff     | ✅ implemented |
| `clawpatrol apply` (local)             | ✅ implemented |
| `clawpatrol config history`            | ✅ implemented |
| Atomic file write + watcher reload     | ✅ implemented |
| Drift warning on apply                 | ⬜ proposed    |
| `--expect` optimistic lock             | ⬜ proposed    |
| `apply --remote` + `POST /api/config`  | ⬜ proposed    |
| `config rollback --to <rev>`           | ⬜ proposed    |
| Reload-time version recording          | ⬜ proposed    |

## Open questions

1. **In-place rewrite vs in-memory swap for remote apply.** Rewriting
   the gateway's config file keeps a single source of truth on disk
   (good for an operator who SSHes in); an in-memory swap avoids
   trusting the filesystem but makes the running config and the on-disk
   file diverge. Probably: write the file *and* swap, atomically.
2. **Directory configs.** `LoadDir` merges multiple `*.hcl` files;
   there's no single byte stream to hash. V1 boot-recording skips
   directory configs. Remote apply of a directory config needs a
   defined canonical serialization (likely `Emit()` of the merged
   result, accepting comment loss).
3. **schema_version bumps.** Should `apply` refuse a config whose
   `schema_version` is newer than the running binary understands?
   (`checkSchemaVersion` already gates load; apply inherits it, but a
   remote apply should return a clear 4xx, not a generic parse error.)
