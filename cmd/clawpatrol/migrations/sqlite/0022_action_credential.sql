-- Carry the resolved credential's bare name on every action row. The
-- dispatch sites already resolve the credential before matching so
-- credential-pinned rules can fire; without recording it the exported
-- action fixture replays with an empty credential and `clawpatrol test`
-- can report a different verdict than the gateway produced. NULL for
-- pre-existing rows and for events that never resolved a credential.

ALTER TABLE actions ADD COLUMN credential TEXT;

INSERT INTO _schema (version) VALUES (22);
