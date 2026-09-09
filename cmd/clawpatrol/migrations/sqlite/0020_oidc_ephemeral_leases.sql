-- OIDC ephemeral enrollment replay reservations and peer leases.
--
-- Raw OIDC tokens are never stored. Replay prevention keys are derived from
-- verified claims (`iss`, `sub`, `jti` when present) or from a SHA-256 token
-- hash when `jti` is absent.
CREATE TABLE IF NOT EXISTS oidc_replay_reservations (
  replay_key  TEXT PRIMARY KEY,
  issuer      TEXT NOT NULL,
  subject     TEXT NOT NULL,
  jwt_id      TEXT,
  token_hash  TEXT NOT NULL,
  enrollment  TEXT NOT NULL,
  profile     TEXT NOT NULL,
  reserved_ns INTEGER NOT NULL,
  expires_ns  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oidc_replay_reservations_expires_ns ON oidc_replay_reservations(expires_ns);
CREATE INDEX IF NOT EXISTS oidc_replay_reservations_subject ON oidc_replay_reservations(issuer, subject);

CREATE TABLE IF NOT EXISTS oidc_ephemeral_leases (
  peer_ip      TEXT PRIMARY KEY,
  pubkey       TEXT NOT NULL UNIQUE,
  replay_key   TEXT NOT NULL UNIQUE REFERENCES oidc_replay_reservations(replay_key) ON DELETE RESTRICT,
  issuer       TEXT NOT NULL,
  subject      TEXT NOT NULL,
  enrollment   TEXT NOT NULL,
  profile      TEXT NOT NULL,
  metadata     TEXT,
  created_ns   INTEGER NOT NULL,
  expires_ns   INTEGER NOT NULL,
  revoked_ns   INTEGER
);
CREATE INDEX IF NOT EXISTS oidc_ephemeral_leases_expires_ns ON oidc_ephemeral_leases(expires_ns);
CREATE INDEX IF NOT EXISTS oidc_ephemeral_leases_subject ON oidc_ephemeral_leases(issuer, subject);
