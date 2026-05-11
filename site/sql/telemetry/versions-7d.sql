-- Version distribution among gateways active in the last 7 days.
SELECT version, COUNT(*) AS count
FROM gateways
WHERE last_seen > unixepoch() - 7 * 86400
GROUP BY version
ORDER BY count DESC, version;
