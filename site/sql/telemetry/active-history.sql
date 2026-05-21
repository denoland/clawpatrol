-- Active gateways per day, from snapshots written by the cron.
SELECT day, count AS active_gateways
  FROM telemetry_snapshots
 WHERE metric = 'active'
 ORDER BY day DESC
 LIMIT 30;
