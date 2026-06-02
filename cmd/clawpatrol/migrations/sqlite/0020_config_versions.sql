-- Config version history for `clawpatrol apply`.
--
-- The gateway config has always been read-only-from-file: edits land
-- via SSH push / git, and the running gateway picks them up through the
-- file watcher. There was no record of WHAT changed, WHO changed it, or
-- WHEN — and no way to see the sequence of configs a gateway has run.
--
-- This table is the audit trail. `clawpatrol apply` validates a config,
-- shows a semantic diff against the last applied version, and on
-- confirmation records a row here. The gateway also records the config
-- it loads at boot, so the trail starts from the currently-running
-- config rather than from the first apply.
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
  applied_by     TEXT NOT NULL DEFAULT '',
  note           TEXT NOT NULL DEFAULT '',
  applied_ns     INTEGER NOT NULL
);

CREATE INDEX config_versions_applied_ns_idx ON config_versions(applied_ns);
