-- Drop the ephemeral-peer remnants left over from the
-- per-process WireGuard model (removed when the daemon took over
-- both transports). Nothing reads or writes these any more.
--
-- Order matters: clear rows that would be left dangling before
-- dropping the columns / tables they reference.
DELETE FROM wg_peers WHERE ephemeral = 1;
DROP TABLE IF EXISTS ephemeral_peers;
ALTER TABLE wg_peers DROP COLUMN ephemeral;
ALTER TABLE wg_peers DROP COLUMN parent_ip;
