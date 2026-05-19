-- Operation-scoped capability token hashes for public async HITL status polling.
-- Raw status tokens are returned only in the initial 202 status_url and are
-- never persisted.

ALTER TABLE hitl_operations ADD COLUMN status_token_hash TEXT;

CREATE UNIQUE INDEX hitl_operations_status_token_idx
  ON hitl_operations(id, status_token_hash)
  WHERE status_token_hash IS NOT NULL;

INSERT INTO _schema (version) VALUES (18);
