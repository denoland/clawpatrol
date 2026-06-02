-- Write today's roll-up rows into telemetry_snapshots. Idempotent:
-- rerunning the same UTC day overwrites that day's rows. The
-- scheduled worker handler computes the same numbers via prepared
-- statements; this file lets you seed or backfill manually with
--   npx wrangler d1 execute TELEMETRY_DB --remote --file sql/snapshot.sql
INSERT OR REPLACE INTO telemetry_snapshots (day, metric, bucket, count)
SELECT CAST(strftime('%Y%m%d', 'now') AS INTEGER), 'active', '',
       COUNT(*)
  FROM gateways
 WHERE last_seen > unixepoch() - 7 * 86400;

INSERT OR REPLACE INTO telemetry_snapshots (day, metric, bucket, count)
SELECT CAST(strftime('%Y%m%d', 'now') AS INTEGER), 'transport',
       COALESCE(transport, '(unknown)'),
       COUNT(*)
  FROM gateways
 WHERE last_seen > unixepoch() - 7 * 86400
 GROUP BY transport;

INSERT OR REPLACE INTO telemetry_snapshots (day, metric, bucket, count)
SELECT CAST(strftime('%Y%m%d', 'now') AS INTEGER), 'platform',
       COALESCE(os, '?') || '/' || COALESCE(arch, '?'),
       COUNT(*)
  FROM gateways
 WHERE last_seen > unixepoch() - 7 * 86400
 GROUP BY os, arch;

INSERT OR REPLACE INTO telemetry_snapshots (day, metric, bucket, count)
SELECT CAST(strftime('%Y%m%d', 'now') AS INTEGER), 'version',
       version,
       COUNT(*)
  FROM gateways
 WHERE last_seen > unixepoch() - 7 * 86400
 GROUP BY version;
