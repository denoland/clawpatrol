-- Per-peer API tokens.
--
-- Issued at onboard-approve time alongside the WG keypair, returned
-- to the client as part of the /api/onboard/poll response so it can
-- be persisted next to ca.crt. Subsequent client requests to gated
-- API endpoints (currently /api/env-pushdown) prove they're a known
-- peer by sending the token as `Authorization: Bearer <token>`.
--
-- Stored as a SHA-256 hash so a DB leak doesn't yield usable
-- bearers. The lookup compares hashes.
--
-- A peer may have multiple tokens active (e.g. join from two
-- machines reusing the same hostname → two onboards, two tokens) —
-- forget_peer cascades drop all rows for the IP.
CREATE TABLE IF NOT EXISTS peer_api_tokens (
  token_hash TEXT PRIMARY KEY,
  peer_ip    TEXT NOT NULL,
  created_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS peer_api_tokens_peer_ip ON peer_api_tokens(peer_ip);
