package main

import (
	"path/filepath"
	"testing"
)

func TestOpenDBSchemaV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clawpatrol.db")

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	for _, table := range []string{"actions", "credentials", "devices", "wg_peers"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}

	var v int
	if err := db.QueryRow("SELECT version FROM _schema").Scan(&v); err != nil {
		t.Fatalf("_schema: %v", err)
	}
	if v != 1 {
		t.Errorf("schema version: want 1, got %d", v)
	}

	// Reopen — runner must be idempotent.
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := OpenDB(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	rows := 0
	if err := db2.QueryRow("SELECT COUNT(*) FROM _schema").Scan(&rows); err != nil {
		t.Fatalf("re-_schema: %v", err)
	}
	if rows != 1 {
		t.Errorf("_schema rows after reopen: want 1, got %d", rows)
	}
}
