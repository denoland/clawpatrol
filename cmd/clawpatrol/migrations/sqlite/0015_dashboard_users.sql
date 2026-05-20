-- 0015_dashboard_users — dashboard operator accounts.
--
-- Today: a single row (username='root') created at first-run, holding
-- the bcrypt hash of the dashboard password. Future rows will carry
-- additional operator identities (extra username/password pairs, OAuth
-- accounts) once those land.
--
-- The dashboard gate REFUSES to serve any management endpoint until a
-- root row exists. That keeps the "no auth configured" window from
-- ever overlapping with stored credentials / profile state: every
-- mutation endpoint sits behind the gate, so credentials cannot be
-- created before the password is set.

CREATE TABLE dashboard_users (
  username      TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_ns    INTEGER NOT NULL,
  updated_ns    INTEGER NOT NULL
);
