# RFC: `clawpatrol apply`

Status: **implemented (local, DB-authoritative with locking); remote
apply proposed.**
Related: R&D standup 2026-06-01 (config editing + `cloudpatrol apply`),
[doc/roles.md](roles.md) (RBAC, the auth basis for remote apply).

## Problem

The gateway config was read-only-from-file: edit `gateway.hcl`, `scp`
it to the box, let the file watcher pick it up. No record of what
changed, who, or when; no diff before it went live; an invalid file
that reached the watcher could break a running gateway; no rollback.
"Push from CI" was just `scp` with an SSH key.

The first cut of this work added a `config_versions` audit table but
left the **HCL file as the source of truth** — which doesn't actually
solve anything, because there's no single authoritative store to lock
against. Two `apply`s, or an `apply` racing an `scp`, still clobber each
other. That's the hole this RFC closes.

## Model — exactly Terraform's

Terraform is safe because the **state backend is authoritative**, every
change takes a **lock**, and writes check a **serial**. We do the same:

- **State backend** = `config_versions` in the gateway DB. The latest
  row is the deployed config; its `id` is the **serial**.
- **The gateway runs from the backend**, not from a watched file. The
  `gateway <file>` argument only *seeds* the backend on first boot
  (when it's empty). After that the file is the **desired** input to
  `apply` — like a `.tf` — and editing it on disk no longer changes the
  running config. Only an `apply` does.
- **Lock** (`config_lock`, single row): `apply` holds it for the
  plan→write→release window. A concurrent `apply` fails with "config is
  locked by X". A lock left by a crashed apply is stolen after
  `configLockStaleAfter` (10m) or cleared with `clawpatrol config
  unlock`.
- **Serial CAS**: the new version inserts only if the latest serial is
  still the one the plan was computed against, so a stale apply is
  rejected even if the lock was forced mid-flight.

This eliminates every clobber path from the first cut:

| Scenario | Behavior now |
| --- | --- |
| Two `apply` at once | Second fails: "config is locked by X". |
| `scp`/`vim` on the box | No effect on the running gateway — it reads the backend, not the file. |
| Stale plan applied | Serial CAS rejects it: "state changed during apply". |
| Crashed apply holding the lock | Auto-stolen after 10m, or `config unlock`. |

## Commands (implemented)

```
clawpatrol plan   <config.hcl>   diff desired file vs deployed state (read-only, lock-free)
clawpatrol apply  [-y] [--by w] [--note t] <config.hcl>
                                 re-plan under lock, confirm, CAS-record a new serial
clawpatrol config history <config.hcl>   list versions (serial, time, revision, who, note)
clawpatrol config unlock  <config.hcl>   force-release a stuck lock
```

The running gateway polls the backend serial (`watchConfig`) and
hot-swaps policy when a new version lands — typically within ~3s of an
apply.

## Real output

```
$ clawpatrol plan gateway.hcl
revision: b5e35ff59d74  (1 endpoints, 1 profiles)
deployed: (none — backend is empty, this seeds serial 1)
changes: +6  -0  ~0
  + credential github
  + endpoint github
  + gateway
  + profile default
  + rule github-reads
  + rule github-writes

$ clawpatrol apply -y --by divy --note init gateway.hcl
...
Apply complete. serial 1, revision b5e35ff59d74, by divy.

# someone else (or a crashed run) holds the lock:
$ clawpatrol apply -y gateway.hcl
Error: config is locked by bob@laptop since 2026-06-02 19:33:39.000 (apply gateway.hcl)
Another apply may be in progress. If it crashed, run `clawpatrol config unlock gateway.hcl`.

$ clawpatrol config history gateway.hcl
serial 2     2026-06-02 19:33:39.679  9dbd1e870a72  schema=1  by divy  — add newsvc
serial 1     2026-06-02 19:33:39.640  b5e35ff59d74  schema=1  by divy  — init
```

## Semantic diff

`config.PolicyDigest(gw)` renders each operational and policy block to
canonical HCL via the existing deterministic `Emit` hooks, keyed by a
human label. `diffDigests` compares two digests → added / removed /
changed. Reordering blocks or editing a comment is **no change**; only
a real content change to a block registers.

## Remote apply — proposed (the `scp` killer)

Local `apply` already coordinates with the running gateway through the
shared DB + lock, so on the gateway host `scp` is gone. To apply from a
laptop or CI **without** filesystem/DB access to the box, add
`clawpatrol apply --remote <gateway-url> config.hcl`:

1. CLI validates + compiles locally (fail fast, no round-trip).
2. CLI POSTs the bytes to `POST /api/config` with `If-Match: <serial>`.
3. The gateway runs the same lock → plan → CAS-record → release
   in-process, attributing `applied_by` to the caller's RBAC identity,
   and returns the new serial.
4. `412 Precondition Failed` on a serial mismatch (the lock + CAS,
   surfaced over HTTP).

Reuses what exists: auth = the dashboard gate + [RBAC roles](roles.md)
(apply is an `admin`/global-`editor` action); transport = the gateway's
existing TS/WG/public listener; storage/diff/lock = identical to local.
CI gets a scoped role instead of a root SSH key.

## Implementation status

| Piece                                       | Status        |
| ------------------------------------------- | ------------- |
| `config_versions` backend + serial           | ✅ implemented |
| `config_lock` + acquire/release/steal        | ✅ implemented |
| Serial compare-and-swap insert               | ✅ implemented |
| Gateway runs from backend; serial-poll reload | ✅ implemented |
| `plan` / `apply` / `config history` / `config unlock` | ✅ implemented |
| Semantic block diff (`PolicyDigest`)          | ✅ implemented |
| `apply --remote` + `POST /api/config`         | ⬜ proposed    |
| `config rollback --to <serial>`               | ⬜ proposed    |

## Open questions

1. **Directory configs.** `LoadDir` merges multiple `*.hcl`; there's no
   single byte stream to seed/serve. Boot skips seeding for a directory
   config and runs it file-only (serial 0). A backend representation
   would need a canonical serialization (likely `Emit()` of the merged
   result, accepting comment loss).
2. **Operator who edits the file and restarts.** Under DB-authority the
   restart re-runs the backend, not the edited file — intentional (it's
   `terraform apply` against a checked-in `.tf`), but it's a behavior
   change worth a clear boot log line (present: "running deployed serial
   N (started from file …)").
3. **schema_version downgrade.** A backend version newer than the
   running binary fails `loadConfigBytes`; `watchConfig` logs and skips
   it. A remote apply should return a clear 4xx rather than a generic
   parse error.
