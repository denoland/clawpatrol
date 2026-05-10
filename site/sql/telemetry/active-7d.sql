-- Distinct gateways that pinged in the last 7 days.
SELECT COUNT(*) AS active_gateways
FROM gateways
WHERE last_seen > unixepoch() - 7 * 86400;
