package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func newCVTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRecordConfigVersionDedup(t *testing.T) {
	db := newCVTestDB(t)
	rev1, inserted, err := recordConfigVersion(db, []byte("gateway {}\n"), 1, "alice", "first")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if !inserted {
		t.Fatal("first record should insert")
	}
	// Same bytes → no new row.
	rev2, inserted, err := recordConfigVersion(db, []byte("gateway {}\n"), 1, "bob", "dup")
	if err != nil {
		t.Fatalf("record dup: %v", err)
	}
	if inserted {
		t.Fatal("identical revision must not insert a second row")
	}
	if rev1 != rev2 {
		t.Fatalf("same bytes → same revision, got %s vs %s", rev1, rev2)
	}
	// Different bytes → new row.
	if _, inserted, _ := recordConfigVersion(db, []byte("gateway {}\n# changed\n"), 1, "alice", "second"); !inserted {
		t.Fatal("changed bytes must insert")
	}
	versions, err := listConfigVersions(db, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("want 2 versions, got %d", len(versions))
	}
	// Newest first.
	if versions[0].Note != "second" {
		t.Fatalf("want newest-first ordering, got note %q", versions[0].Note)
	}
}

func TestLatestConfigVersionEmpty(t *testing.T) {
	db := newCVTestDB(t)
	if _, ok, err := latestConfigVersion(db); err != nil || ok {
		t.Fatalf("empty table: want (_, false, nil), got ok=%v err=%v", ok, err)
	}
}

func TestDiffDigests(t *testing.T) {
	old := map[string]string{
		"gateway":            "a",
		"endpoint anthropic": "x",
		"endpoint slack":     "y",
	}
	newD := map[string]string{
		"gateway":            "a",  // unchanged
		"endpoint anthropic": "x2", // changed
		"endpoint github":    "z",  // added
		// "endpoint slack" removed
	}
	d := diffDigests(old, newD)
	if len(d.added) != 1 || d.added[0] != "endpoint github" {
		t.Errorf("added = %v", d.added)
	}
	if len(d.removed) != 1 || d.removed[0] != "endpoint slack" {
		t.Errorf("removed = %v", d.removed)
	}
	if len(d.changed) != 1 || d.changed[0] != "endpoint anthropic" {
		t.Errorf("changed = %v", d.changed)
	}
	if d.empty() {
		t.Error("diff should not be empty")
	}
}

func TestDiffDigestsEmpty(t *testing.T) {
	m := map[string]string{"gateway": "a"}
	if !diffDigests(m, m).empty() {
		t.Error("identical digests should diff empty")
	}
}
