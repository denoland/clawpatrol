ALTER TABLE actions ADD COLUMN action_id TEXT;
ALTER TABLE actions ADD COLUMN req_body TEXT;
ALTER TABLE actions ADD COLUMN resp_body TEXT;
ALTER TABLE actions ADD COLUMN resp_headers TEXT;

CREATE INDEX actions_action_id_idx ON actions(action_id);

INSERT INTO _schema (version) VALUES (4);
