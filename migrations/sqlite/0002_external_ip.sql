-- Persist the underlay endpoint IPs each WG peer is dialing in from.
-- Updated whenever a fresh handshake-derived endpoint is observed.
-- Replaces the wg /32 in dashboard listings; the wg ip is a routing
-- artefact, the external addr is what operators actually want to see.

ALTER TABLE devices ADD COLUMN external_ipv4 TEXT;
ALTER TABLE devices ADD COLUMN external_ipv6 TEXT;
