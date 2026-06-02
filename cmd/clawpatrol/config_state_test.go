package main

import (
	"testing"
	"time"
)

func TestConfigLockMutualExclusion(t *testing.T) {
	db := newCVTestDB(t)

	ok, _, err := acquireConfigLock(db, "alice@host", "apply x")
	if err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	// Second acquirer is blocked and learns the holder.
	ok, cur, err := acquireConfigLock(db, "bob@host", "apply y")
	if err != nil {
		t.Fatalf("second acquire err: %v", err)
	}
	if ok {
		t.Fatal("second acquire should be blocked while held")
	}
	if cur.Holder != "alice@host" {
		t.Fatalf("contention should report holder alice@host, got %q", cur.Holder)
	}
	// Holder releases; now bob can take it.
	if err := releaseConfigLock(db, "alice@host"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if ok, _, err := acquireConfigLock(db, "bob@host", "apply y"); err != nil || !ok {
		t.Fatalf("acquire after release: ok=%v err=%v", ok, err)
	}
}

func TestConfigLockStealsStale(t *testing.T) {
	db := newCVTestDB(t)
	// Plant a lock older than the staleness window (simulating a crashed
	// apply that never released).
	old := time.Now().Add(-2 * configLockStaleAfter).UnixNano()
	if _, err := db.Exec(
		`INSERT INTO config_lock (id, holder, reason, locked_ns) VALUES (0, ?, ?, ?)`,
		"ghost@host", "crashed", old,
	); err != nil {
		t.Fatalf("plant: %v", err)
	}
	ok, _, err := acquireConfigLock(db, "alice@host", "apply x")
	if err != nil || !ok {
		t.Fatalf("should steal stale lock: ok=%v err=%v", ok, err)
	}
	cur, held, _ := readConfigLock(db)
	if !held || cur.Holder != "alice@host" {
		t.Fatalf("after steal holder should be alice@host, got %q held=%v", cur.Holder, held)
	}
}

func TestForceUnlock(t *testing.T) {
	db := newCVTestDB(t)
	_, _, _ = acquireConfigLock(db, "alice@host", "apply x")
	released, err := forceUnlockConfigLock(db)
	if err != nil || !released {
		t.Fatalf("force unlock: released=%v err=%v", released, err)
	}
	if _, held, _ := readConfigLock(db); held {
		t.Fatal("lock should be gone after force unlock")
	}
	// Idempotent on an unlocked backend.
	if released, _ := forceUnlockConfigLock(db); released {
		t.Fatal("second force unlock should report nothing released")
	}
}

func TestRecordConfigVersionCAS(t *testing.T) {
	db := newCVTestDB(t)

	// Seed serial 1 from an empty backend (expected serial 0).
	rev1, s1, ok, err := recordConfigVersionCAS(db, []byte("gateway {}\n"), 1, 0)
	if err != nil || !ok {
		t.Fatalf("seed: ok=%v err=%v", ok, err)
	}
	if s1 != 1 {
		t.Fatalf("first serial = %d, want 1", s1)
	}

	// A stale writer that still thinks the latest is 0 is rejected.
	if _, _, ok, err := recordConfigVersionCAS(db, []byte("gateway {}\n# x\n"), 1, 0); err != nil || ok {
		t.Fatalf("stale CAS should fail: ok=%v err=%v", ok, err)
	}

	// A writer with the current serial succeeds and advances it.
	rev2, s2, ok, err := recordConfigVersionCAS(db, []byte("gateway {}\n# x\n"), 1, s1)
	if err != nil || !ok {
		t.Fatalf("fresh CAS: ok=%v err=%v", ok, err)
	}
	if s2 != 2 {
		t.Fatalf("second serial = %d, want 2", s2)
	}
	if rev1 == rev2 {
		t.Fatal("different content should yield different revisions")
	}

	cur, err := currentSerial(db)
	if err != nil || cur != 2 {
		t.Fatalf("currentSerial = %d err=%v, want 2", cur, err)
	}
	content, serial, present, err := activeConfig(db)
	if err != nil || !present || serial != 2 || string(content) != "gateway {}\n# x\n" {
		t.Fatalf("activeConfig = serial %d present=%v err=%v", serial, present, err)
	}
}
