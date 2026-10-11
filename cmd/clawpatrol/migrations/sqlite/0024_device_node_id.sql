-- 0024_device_node_id — record the Tailscale node a device row belongs
-- to, so a peer IP with no row of its own is only ever folded onto an
-- existing device when the control plane says both addresses belong to
-- the same node.
--
-- The column is the sole identity an alias may be derived from. A row
-- that predates this migration carries NULL, so the node pass never
-- matches it; it fills in the next time a node is observed holding the
-- row's address, on an authenticated path (onboard claim, tsnet
-- register) or through a WhoIs that names the address as its own.
--
-- That first binding inherits the devices table's own assumption, that
-- the row's IP is the device: an unbound row is bound to whichever node
-- holds its address at that moment, which after a delete-and-reuse is a
-- different node. From the second observation on, the binding is what
-- refuses the swap. Closing the first-observation window needs the
-- bindings backfilled from a node enumeration at upgrade, or tailnet
-- device deletion wired to drop the row.

ALTER TABLE devices ADD COLUMN ts_node_id TEXT;
