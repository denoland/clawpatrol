-- Daily roll-ups of gateway telemetry. The `gateways` table only
-- holds the latest ping per instance, so historical counts have to
-- be snapshotted. Populated by the worker's scheduled() handler.
--
-- Tall shape: one row per (day, metric, bucket). New dimensions or
-- new bucket values (a new OS/arch, a new transport) need no schema
-- change. Active count uses bucket=''.
CREATE TABLE telemetry_snapshots (
  day    INTEGER NOT NULL,  -- yyyymmdd, UTC
  metric TEXT    NOT NULL,  -- 'active' | 'transport' | 'platform' | 'version'
  bucket TEXT    NOT NULL,  -- '' for 'active'
  count  INTEGER NOT NULL,
  PRIMARY KEY (day, metric, bucket)
);
