-- 0011_credentials_global — credentials carry one secret, not one per
-- profile. Before this migration `credential_secrets` and `credentials`
-- were both keyed by (… , profile, …) so a single HCL credential
-- declaration silently fanned out into N secret rows, one per profile
-- that referenced it. That implicit fan-out hides intent: if two
-- profiles need different secret material, the operator should declare
-- two credentials in HCL and bind each to its own endpoint.
--
-- This migration collapses both tables to one row per credential by
-- keeping the most recently updated row per credential (resp. per
-- credential+slot for credential_secrets). Operators on a single
-- profile (the common case) are unaffected; operators who had distinct
-- secrets on multiple profiles for the same credential keep whichever
-- one they last touched, and need to re-enter the others against
-- separately declared credentials.

CREATE TABLE credential_secrets_v2 (
  credential TEXT NOT NULL,
  slot       TEXT NOT NULL,
  value      TEXT NOT NULL,
  updated_ns INTEGER NOT NULL,
  PRIMARY KEY (credential, slot)
);

INSERT INTO credential_secrets_v2 (credential, slot, value, updated_ns)
SELECT cs.credential, cs.slot, cs.value, cs.updated_ns
  FROM credential_secrets cs
  JOIN (
    SELECT credential, slot, MAX(updated_ns) AS mx
      FROM credential_secrets
     GROUP BY credential, slot
  ) m
    ON m.credential = cs.credential
   AND m.slot       = cs.slot
   AND m.mx         = cs.updated_ns;

DROP TABLE credential_secrets;
ALTER TABLE credential_secrets_v2 RENAME TO credential_secrets;

CREATE TABLE credentials_v2 (
  id             TEXT PRIMARY KEY,
  access_token   TEXT,
  token_type     TEXT,
  refresh_token  TEXT,
  expiry_ns      INTEGER,
  updated_ns     INTEGER NOT NULL,
  display_name   TEXT,
  avatar_url     TEXT
);

INSERT INTO credentials_v2 (id, access_token, token_type, refresh_token, expiry_ns, updated_ns, display_name, avatar_url)
SELECT c.id, c.access_token, c.token_type, c.refresh_token, c.expiry_ns, c.updated_ns, c.display_name, c.avatar_url
  FROM credentials c
  JOIN (
    SELECT id, MAX(updated_ns) AS mx
      FROM credentials
     GROUP BY id
  ) m
    ON m.id = c.id
   AND m.mx = c.updated_ns;

DROP TABLE credentials;
ALTER TABLE credentials_v2 RENAME TO credentials;
