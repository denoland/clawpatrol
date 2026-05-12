-- Pin each join credential to the public IP it registered from.
--
-- The agent host hits /api/onboard/start over the public internet
-- (before its WG tunnel exists). r.RemoteAddr at that call is its
-- public address; we persist it on the peer_api_tokens row that
-- /api/onboard/approve mints. Gated API calls (env-pushdown,
-- ephemeral peer) check the WG peer's underlay endpoint against
-- this pair; a mismatch (different v4, different v6, or v6 on a
-- v4-only registration) tears the tunnel down and revokes the
-- token. Matches the "leaked join credential" guarantee in
-- site/doc/security-model.md.
--
-- Both columns are nullable: a registration sees only one address
-- family on its bootstrap HTTP request, so the other column stays
-- NULL and a request from the unregistered family fails the check.
ALTER TABLE peer_api_tokens ADD COLUMN approved_ipv4 TEXT;
ALTER TABLE peer_api_tokens ADD COLUMN approved_ipv6 TEXT;
