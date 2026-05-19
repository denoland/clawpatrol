-- 0017_ephemeral_peers — per-process tsnet ephemeral peer attribution.
--
-- ephemeralParentByIP / ephemeralProfileByIP used to live in memory only.
-- A gateway restart wiped them, so any `clawpatrol run` that was alive
-- across the restart started showing as its own dashboard row (named
-- "clawpatrol-run-<pid>") instead of folding into its parent device.
-- Mirror the maps into a table so the mappings survive restarts.

CREATE TABLE ephemeral_peers (
  ip         TEXT PRIMARY KEY,    -- ephemeral tsnet IP (100.x.x.x)
  parent_ip  TEXT NOT NULL,       -- parent device IP that owns this run
  profile    TEXT NOT NULL,
  created_ns INTEGER NOT NULL
);
