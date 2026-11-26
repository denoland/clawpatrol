-- Enrollment columns on wg_peers.
--
-- Workloads self-enroll as transient WireGuard peers through a configured
-- authorizer (see the top-level enrollment block). enrolled marks
-- reaper-managed peers, so durable onboarded devices (enrolled=0) are never
-- reaped. Liveness is observed from the WireGuard device (rx_bytes
-- progress), so there is no stored expiry.
ALTER TABLE wg_peers ADD COLUMN enrolled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE wg_peers ADD COLUMN subject_key TEXT;
ALTER TABLE wg_peers ADD COLUMN replacement_key TEXT;
ALTER TABLE wg_peers ADD COLUMN display_name TEXT;
ALTER TABLE wg_peers ADD COLUMN owner TEXT;
ALTER TABLE wg_peers ADD COLUMN profile TEXT;
ALTER TABLE wg_peers ADD COLUMN authorizer_type TEXT;
ALTER TABLE wg_peers ADD COLUMN authorizer_name TEXT;
ALTER TABLE wg_peers ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS wg_peers_subject ON wg_peers(subject_key);
CREATE INDEX IF NOT EXISTS wg_peers_replacement ON wg_peers(replacement_key);
