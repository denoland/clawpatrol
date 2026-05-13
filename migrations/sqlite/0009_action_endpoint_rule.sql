-- Carry the dispatching endpoint name and matched rule name on every
-- action row. Needed by `clawpatrol test` (site/doc/clawpatrol-test.md) so the
-- dashboard's per-action exporter can pin fixtures to a specific
-- endpoint and assert the matched rule. Both NULL for pre-existing
-- rows; emitters fill them going forward.

ALTER TABLE actions ADD COLUMN endpoint TEXT;
ALTER TABLE actions ADD COLUMN rule     TEXT;

INSERT INTO _schema (version) VALUES (9);
