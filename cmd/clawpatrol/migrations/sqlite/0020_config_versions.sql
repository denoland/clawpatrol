-- Config version history for `clawpatrol apply`.
--
-- The gateway config has always been read-only-from-file: edits land
-- via SSH push / git, and the running gateway picks them up through the
-- file watcher. There was no record of WHAT changed, WHO changed it, or
-- WHEN — and no way to see the sequence of configs a gateway has run.
--
-- This is the authoritative state backend (Terraform's model): the
-- latest row is the deployed config and its id is the serial. A change
-- is a new row; `clawpatrol apply` records one under a lock with a
-- compare-and-swap on the serial. The gateway records the config it
-- loads at boot so the backend starts from the running config.
--
-- Deliberately OSS-Terraform-shaped: no who/why audit columns. State
-- carries only what conflict detection needs — serial (id), the config
-- bytes, and the revision. (applied_ns is a convenience timestamp for
-- `config history`; the lock row, not this table, records the actor.)
--
-- content holds the exact HCL bytes (comments preserved — we store the
-- operator's file, not an Emit() round-trip). revision is the SHA-256
-- of those bytes, matching the dashboard's X-Config-Revision so the two
-- views agree. A new row is only inserted when the revision differs
-- from the latest, so boot + apply + reload don't pile up duplicates.

CREATE TABLE config_versions (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  revision       TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  content        BLOB NOT NULL,
  applied_ns     INTEGER NOT NULL
);

CREATE INDEX config_versions_applied_ns_idx ON config_versions(applied_ns);
