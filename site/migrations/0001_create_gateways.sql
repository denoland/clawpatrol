-- One row per gateway instance. Upserted on every telemetry ping.
-- Schema mirrors the JSON contract in doc/telemetry.md.
CREATE TABLE gateways (
  instance_id TEXT PRIMARY KEY,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  version     TEXT NOT NULL,
  git_sha     TEXT,
  os          TEXT,
  arch        TEXT,
  go_version  TEXT,
  transport   TEXT,
  uptime_s              INTEGER,
  connected_devices_1h  INTEGER,
  actions_count_1h      INTEGER,
  bytes_in_1h           INTEGER,
  bytes_out_1h          INTEGER,
  payload     TEXT
);

CREATE INDEX gateways_last_seen ON gateways(last_seen);
