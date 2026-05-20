-- 0016_dashboard_sessions — dashboard login sessions.
--
-- Replaces the previous "cookie value = raw password" scheme. The
-- cookie now holds a random 256-bit token; this table stores its
-- SHA-256 hash so a DB leak doesn't double as credential leak.
--
-- Sessions expire at expires_ns (fixed window from creation, capped
-- by dashboard_session_ttl in gateway.hcl, default 24h). Expired
-- rows are deleted lazily on lookup and by a periodic sweeper.
--
-- One row per active session per browser/tab/API client. The
-- username column will carry non-`root` operators once OAuth /
-- per-user accounts land; for now it's always `root`.

CREATE TABLE dashboard_sessions (
  token_hash    TEXT PRIMARY KEY,         -- hex(sha256(cookie_value))
  username      TEXT NOT NULL,
  created_ns    INTEGER NOT NULL,
  expires_ns    INTEGER NOT NULL,
  last_seen_ns  INTEGER NOT NULL
);

CREATE INDEX dashboard_sessions_expires_idx ON dashboard_sessions(expires_ns);
