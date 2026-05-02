-- 0001_initial — clawpatrol persistent state.
--
-- Tables:
--   devices         — onboarded peer identity (WG IP → hostname / profile)
--   wg_peers        — (pubkey, ip) registrations for the wireguard-go device
--   credentials     — per-(integration, profile) OAuth tokens
--   actions         — request event log
--
-- Profile is the tenancy unit: a profile bundles integrations + rulesets
-- in gateway.hcl, devices are bound to a profile, credentials/secrets
-- live per profile. The "user" / "owner" concept is intentionally absent
-- — `clawpatrol join` records (peer ip → profile), the gateway looks up
-- credentials by that profile at MITM time, and the dashboard scopes
-- everything to the operator-selected profile.
--
-- Rules + integrations live in gateway.hcl (HCL is the source of
-- truth for policy). This DB only persists STATE — onboarding,
-- credentials, peer allocations, request history.
--
-- _schema is created by the migration runner before any file runs;
-- this file just inserts the v1 row at the end.

CREATE TABLE devices (
  id           TEXT PRIMARY KEY,         -- WG tunnel IP
  name         TEXT,                     -- hostname from `clawpatrol join`
  profile      TEXT,                     -- assigned profile name (gateway.hcl)
  blocked      INTEGER NOT NULL DEFAULT 0,
  created_ns   INTEGER NOT NULL,
  last_seen_ns INTEGER
);

-- WireGuard peers exist BEFORE a device row is claimed:
-- /api/onboard/approve mints a keypair + allocates an IP and
-- registers the (pubkey, ip) here. /api/onboard/claim creates the
-- matching devices row once the client's wg-quick comes up.
CREATE TABLE wg_peers (
  pubkey   TEXT PRIMARY KEY,
  ip       TEXT NOT NULL UNIQUE,
  added_ns INTEGER NOT NULL
);

CREATE TABLE credentials (
  id             TEXT NOT NULL,          -- 'claude' | 'codex' | 'github' | custom
  profile        TEXT NOT NULL,          -- profile that owns this credential
  access_token   TEXT,
  token_type     TEXT,
  refresh_token  TEXT,
  expiry_ns      INTEGER,
  updated_ns     INTEGER NOT NULL,
  PRIMARY KEY (id, profile)
);

CREATE TABLE actions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ns       INTEGER NOT NULL,
  mode        TEXT,
  agent_ip    TEXT,
  host        TEXT,
  method      TEXT,
  path        TEXT,
  status      INTEGER,
  bytes_in    INTEGER,
  bytes_out   INTEGER,
  ms          INTEGER,
  action      TEXT,
  reason      TEXT,
  req_sha     TEXT,
  resp_sha    TEXT,
  extra       TEXT
);

CREATE INDEX actions_ts_idx       ON actions(ts_ns DESC);
CREATE INDEX actions_agent_ip_idx ON actions(agent_ip, ts_ns DESC);

INSERT INTO _schema (version) VALUES (1);
