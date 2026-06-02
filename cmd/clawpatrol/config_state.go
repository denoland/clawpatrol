package main

// State-backend operations for `clawpatrol apply`: the config lock and
// the compare-and-swap insert that together give Terraform-style
// concurrency safety. config_versions is the authoritative state (its
// latest id is the deployed serial); this file is the locking + CAS
// layer over it. See migrations/sqlite/0021_config_lock.sql.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// configLockStaleAfter bounds how long a lock survives its holder. A
// crashed apply leaves the row behind; once it is older than this, the
// next acquirer steals it (logged). Terraform leaves stale locks for a
// manual force-unlock; we add a TTL so a crashed CLI can't wedge the
// gateway's config forever.
const configLockStaleAfter = 10 * time.Minute

// configLock is the single-row lock state.
type configLock struct {
	Holder   string `json:"holder"`
	Reason   string `json:"reason"`
	LockedNs int64  `json:"locked_ns"`
}

// readConfigLock returns the current lock holder, if any.
func readConfigLock(db *sql.DB) (configLock, bool, error) {
	if db == nil {
		return configLock{}, false, fmt.Errorf("no db")
	}
	var l configLock
	err := db.QueryRow(`SELECT holder, reason, locked_ns FROM config_lock WHERE id = 0`).
		Scan(&l.Holder, &l.Reason, &l.LockedNs)
	if errors.Is(err, sql.ErrNoRows) {
		return configLock{}, false, nil
	}
	if err != nil {
		return configLock{}, false, err
	}
	return l, true, nil
}

// acquireConfigLock takes the lock for holder. Returns (true, _) on
// success. On contention returns (false, current) with the existing
// holder so the caller can report it. A lock older than
// configLockStaleAfter is stolen.
func acquireConfigLock(db *sql.DB, holder, reason string) (bool, configLock, error) {
	if db == nil {
		return false, configLock{}, fmt.Errorf("no db")
	}
	now := time.Now().UnixNano()
	mine := configLock{Holder: holder, Reason: reason, LockedNs: now}

	if _, err := db.Exec(
		`INSERT INTO config_lock (id, holder, reason, locked_ns) VALUES (0, ?, ?, ?)`,
		holder, reason, now,
	); err == nil {
		return true, mine, nil
	}

	// Insert failed — almost certainly the row already exists (lock
	// held). Read it to decide whether to report contention or steal a
	// stale lock.
	cur, held, rerr := readConfigLock(db)
	if rerr != nil {
		return false, configLock{}, rerr
	}
	if !held {
		// Raced with a release between our failed insert and this read;
		// try once more.
		if _, err := db.Exec(
			`INSERT INTO config_lock (id, holder, reason, locked_ns) VALUES (0, ?, ?, ?)`,
			holder, reason, now,
		); err == nil {
			return true, mine, nil
		}
		cur, held, _ = readConfigLock(db)
		if !held {
			return false, configLock{}, fmt.Errorf("config lock: could not acquire")
		}
	}
	if now-cur.LockedNs > int64(configLockStaleAfter) {
		if _, err := db.Exec(
			`UPDATE config_lock SET holder = ?, reason = ?, locked_ns = ? WHERE id = 0`,
			holder, reason, now,
		); err != nil {
			return false, cur, err
		}
		log.Printf("config lock: stole stale lock from %q (held %s)", cur.Holder,
			time.Duration(now-cur.LockedNs).Round(time.Second))
		return true, mine, nil
	}
	return false, cur, nil
}

// releaseConfigLock drops the lock if held by holder. Idempotent.
func releaseConfigLock(db *sql.DB, holder string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	_, err := db.Exec(`DELETE FROM config_lock WHERE id = 0 AND holder = ?`, holder)
	return err
}

// forceUnlockConfigLock drops the lock regardless of holder. Backs
// `clawpatrol config unlock`.
func forceUnlockConfigLock(db *sql.DB) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("no db")
	}
	res, err := db.Exec(`DELETE FROM config_lock WHERE id = 0`)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// recordConfigVersionCAS inserts a new version only if the current
// latest serial equals expectedSerial — the compare-and-swap that
// rejects a stale apply (one whose plan was computed against a serial
// another writer has since superseded). ok is false on a CAS miss;
// serial is the new row's id on success.
func recordConfigVersionCAS(db *sql.DB, content []byte, schemaVersion int, appliedBy, note string, expectedSerial int64) (revision string, serial int64, ok bool, err error) {
	if db == nil {
		return "", 0, false, fmt.Errorf("no db")
	}
	revision = revisionForBytes(content)
	res, err := db.Exec(
		`INSERT INTO config_versions (revision, schema_version, content, applied_by, note, applied_ns)
		 SELECT ?, ?, ?, ?, ?, ?
		  WHERE (SELECT COALESCE(MAX(id), 0) FROM config_versions) = ?`,
		revision, schemaVersion, content, appliedBy, note, time.Now().UnixNano(), expectedSerial,
	)
	if err != nil {
		return "", 0, false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return revision, 0, false, nil
	}
	id, _ := res.LastInsertId()
	return revision, id, true, nil
}

// activeConfig returns the deployed config: the content + serial of the
// latest version. ok is false when the backend is empty (no config has
// been seeded/applied yet).
func activeConfig(db *sql.DB) (content []byte, serial int64, ok bool, err error) {
	v, found, err := latestConfigVersion(db)
	if err != nil || !found {
		return nil, 0, false, err
	}
	return v.Content, v.ID, true, nil
}

// currentSerial returns the latest serial (0 when the backend is empty).
func currentSerial(db *sql.DB) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("no db")
	}
	var s int64
	err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM config_versions`).Scan(&s)
	return s, err
}
