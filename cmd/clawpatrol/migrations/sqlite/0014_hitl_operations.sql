-- Durable metadata for async HITL approval-grant operations.
--
-- This table intentionally stores operation state, owner binding, safe
-- display metadata, and versioned request fingerprints only. It must not
-- store raw request bodies, raw Authorization/Cookie values, upstream
-- secrets, or replayable request material.

CREATE TABLE hitl_operations (
  id                            TEXT PRIMARY KEY,
  state                         TEXT NOT NULL,
  version                       INTEGER NOT NULL DEFAULT 1,

  profile_id                    TEXT NOT NULL,
  principal_id                  TEXT NOT NULL,
  endpoint_id                   TEXT NOT NULL,
  approval_rule_id              TEXT NOT NULL,
  approver_id                   TEXT NOT NULL,

  method                        TEXT NOT NULL,
  scheme                        TEXT NOT NULL,
  host                          TEXT NOT NULL,
  redacted_path                 TEXT NOT NULL,
  redacted_query                TEXT,
  redacted_headers_json         TEXT,

  auth_binding_id               TEXT NOT NULL,
  fingerprint_version           TEXT NOT NULL,
  hmac_key_id                   TEXT NOT NULL,
  request_fingerprint           TEXT NOT NULL,

  created_ns                    INTEGER NOT NULL,
  sync_wait_deadline_ns         INTEGER NOT NULL,
  approval_expires_ns           INTEGER NOT NULL,
  retry_expires_ns              INTEGER,
  expired_reason                TEXT,
  terminal_ns                   INTEGER,
  terminal_retention_expires_ns INTEGER,

  upstream_called               INTEGER NOT NULL DEFAULT 0,
  grant_consumed_ns             INTEGER,
  grant_consumed_by             TEXT,
  approver_message_ref          TEXT,
  dashboard_ref                 TEXT,
  last_error                    TEXT
);

CREATE INDEX hitl_operations_owner_idx ON hitl_operations(profile_id, principal_id, id);
CREATE INDEX hitl_operations_state_idx ON hitl_operations(state, approval_expires_ns, retry_expires_ns);
CREATE INDEX hitl_operations_terminal_retention_idx ON hitl_operations(terminal_retention_expires_ns)
  WHERE terminal_retention_expires_ns IS NOT NULL;

INSERT INTO _schema (version) VALUES (14);
