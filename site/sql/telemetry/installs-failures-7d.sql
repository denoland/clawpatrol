-- Top failure reasons in the last 7 days. Useful for catching
-- regressions in install.sh (unsupported arch, missing curl,
-- sha256 mismatch, ...).
SELECT
  COALESCE(reason, '(unknown)') AS reason,
  COUNT(*) AS count
FROM installs
WHERE received_at > unixepoch() - 7 * 86400
  AND event = 'failed'
GROUP BY reason
ORDER BY count DESC, reason;
