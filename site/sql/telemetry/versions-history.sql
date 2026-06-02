-- Version split per day from snapshots. Long form, most-recent first.
SELECT day, bucket AS version, count
  FROM telemetry_snapshots
 WHERE metric = 'version'
 ORDER BY day DESC, count DESC, version
 LIMIT 90;
