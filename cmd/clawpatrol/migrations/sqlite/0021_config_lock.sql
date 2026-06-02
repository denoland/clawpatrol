-- State lock for `clawpatrol apply`, modeled on Terraform's state
-- locking (DynamoDB LockID item).
--
-- config_versions is the authoritative state backend: the latest row's
-- id is the serial of the deployed config. A change is a new row. To
-- make concurrent changes safe, apply takes this lock for the duration
-- of the plan→write→release window. The single-row PRIMARY KEY (id = 0)
-- is the mutual-exclusion primitive: a second acquirer's INSERT fails
-- the uniqueness check and reports who holds it.
--
-- A lock left behind by a crashed apply is recoverable two ways:
-- `clawpatrol config unlock`, or automatic steal once locked_ns is
-- older than the staleness window (see configLockStaleAfter).

CREATE TABLE config_lock (
  id        INTEGER PRIMARY KEY CHECK (id = 0),
  holder    TEXT NOT NULL,
  reason    TEXT NOT NULL DEFAULT '',
  locked_ns INTEGER NOT NULL
);
