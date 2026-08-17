ALTER TABLE actions ADD COLUMN req_transformed INTEGER NOT NULL DEFAULT 0;

INSERT INTO _schema (version) VALUES (21);
