-- Transport split per day. Long form so new buckets don't need
-- a schema or query change. Most-recent first.
SELECT day, bucket AS transport, count
  FROM telemetry_snapshots
 WHERE metric = 'transport'
 ORDER BY day DESC, count DESC, transport
 LIMIT 90;
