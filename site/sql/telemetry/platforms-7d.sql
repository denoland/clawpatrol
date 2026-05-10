-- OS / arch breakdown among gateways active in the last 7 days.
SELECT
  COALESCE(os, '?') || '/' || COALESCE(arch, '?') AS platform,
  COUNT(*) AS count
FROM gateways
WHERE last_seen > unixepoch() - 7 * 86400
GROUP BY platform
ORDER BY count DESC, platform;
