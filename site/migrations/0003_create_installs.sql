-- One row per `install.sh` invocation that pinged home. Append-only;
-- install_id is generated client-side per script run, so duplicate
-- events for the same id (retries from the same shell) collapse via
-- INSERT OR REPLACE in the worker.
CREATE TABLE installs (
  install_id  TEXT PRIMARY KEY,
  received_at INTEGER NOT NULL,
  event       TEXT NOT NULL,   -- 'completed' | 'failed'
  os          TEXT,
  arch        TEXT,
  version     TEXT,
  from_source INTEGER,         -- 0 | 1
  reason      TEXT             -- failure message, empty on completed
);

CREATE INDEX installs_received_at ON installs(received_at);
CREATE INDEX installs_event       ON installs(event);
