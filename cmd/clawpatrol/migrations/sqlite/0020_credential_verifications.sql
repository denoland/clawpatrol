-- 0020_credential_verifications — record the outcome of the
-- credential-specific verification call (auth.test for Slack,
-- users/@me for Discord, …) that runs synchronously when the
-- dashboard saves a connect form. Lets /api/state distinguish
-- "tokens were pasted" from "tokens actually work" without us
-- having to re-verify on every poll.

CREATE TABLE credential_verifications (
  credential  TEXT PRIMARY KEY,
  status      TEXT NOT NULL, -- 'ok' | 'failed'
  error       TEXT,
  verified_ns INTEGER NOT NULL
);
