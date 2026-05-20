-- Operation-scoped capability token hashes for public async HITL status polling.
-- Raw status tokens are returned only in the initial 202 status_url and are
-- never persisted.

ALTER TABLE hitl_operations ADD COLUMN status_token_hash TEXT;

INSERT INTO _schema (version) VALUES (18);
