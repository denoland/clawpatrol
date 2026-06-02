-- Successful installs in the last 7 days, broken down by os/arch.
SELECT
  COALESCE(os, '?') || '/' || COALESCE(arch, '?') AS platform,
  COUNT(*) AS count
FROM installs
WHERE received_at > unixepoch() - 7 * 86400
  AND event = 'completed'
GROUP BY platform
ORDER BY count DESC, platform;
