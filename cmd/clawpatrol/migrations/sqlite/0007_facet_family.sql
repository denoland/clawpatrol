-- Adds the `family` column to the actions table so analytics queries
-- can filter and group by protocol family ("https" / "sql" / "k8s" /
-- future plugin names). The existing `extra` TEXT column, unused
-- until now, becomes the JSON facets payload: each event stores the
-- per-family Report() output (HTTPS: method/path/status, SQL: verb/
-- tables/functions/statement, k8s: verb/resource/namespace/name/
-- params, ...). Schema-driven dashboard rendering walks the JSON
-- via the field list returned by GET /api/facets.
--
-- Legacy rows have family = '' and no extra JSON; the dashboard
-- falls back to the old method/path columns for those, so the
-- migration doesn't have to backfill blindly.

ALTER TABLE actions ADD COLUMN family TEXT NOT NULL DEFAULT '';
CREATE INDEX actions_family_idx ON actions(family, ts_ns DESC);

INSERT INTO _schema (version) VALUES (7);
