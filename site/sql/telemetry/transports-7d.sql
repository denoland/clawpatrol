-- Tailscale vs WireGuard split among gateways active in the last 7 days.
SELECT COALESCE(transport, '(unknown)') AS transport, COUNT(*) AS count
FROM gateways
WHERE last_seen > unixepoch() - 7 * 86400
GROUP BY transport
ORDER BY count DESC, transport;
