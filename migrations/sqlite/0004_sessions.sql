-- Sessions: one coding-agent conversation per (agent_ip, type, id).
-- Persisted so dashboard surfaces survive gateway restart.
--
-- Identity: (agent_ip, type, id). id is the agent's own session/
-- conversation hash from request metadata; for agents that don't
-- expose one, recordLLMUsage extends the most-recent same-type
-- session instead of opening a new row.
--
-- Retention is enforced by the sweeper via last_at — sessions can
-- revive on new activity at any time, so there's no "closed"
-- intermediate state. Hard delete past session_keep.

CREATE TABLE IF NOT EXISTS sessions (
  agent_ip   TEXT    NOT NULL,
  type       TEXT    NOT NULL,
  id         TEXT    NOT NULL,
  title      TEXT,
  model      TEXT,
  tokens_in  INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0,
  ctx_used   INTEGER NOT NULL DEFAULT 0,
  ctx_max    INTEGER NOT NULL DEFAULT 0,
  reqs       INTEGER NOT NULL DEFAULT 0,
  first_at   INTEGER NOT NULL,
  last_at    INTEGER NOT NULL,
  PRIMARY KEY (agent_ip, type, id)
);

CREATE INDEX IF NOT EXISTS sessions_last_at_idx ON sessions(last_at);
