-- Install events in the last 7 days, split by outcome.
SELECT event, COUNT(*) AS count
FROM installs
WHERE received_at > unixepoch() - 7 * 86400
GROUP BY event
ORDER BY count DESC;
