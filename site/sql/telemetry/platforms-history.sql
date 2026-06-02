-- OS/arch split per day from snapshots. Long form, most-recent first.
SELECT day, bucket AS platform, count
  FROM telemetry_snapshots
 WHERE metric = 'platform'
 ORDER BY day DESC, count DESC, platform
 LIMIT 90;
