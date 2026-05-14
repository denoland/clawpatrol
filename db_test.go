package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenDB_FreshCreateIs0600 covers the common case: state_dir is
// fresh, sqlite creates clawpatrol.db with its default mode (0644 on
// systems with umask 022), OpenDB should tighten it.
func TestOpenDB_FreshCreateIs0600(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "clawpatrol.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	for _, name := range []string{"clawpatrol.db", "clawpatrol.db-wal", "clawpatrol.db-shm"} {
		p := filepath.Join(dir, name)
		st, err := os.Stat(p)
		if err != nil {
			// WAL/SHM are created on first write; tolerate absence.
			continue
		}
		if mode := st.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %#o, want 0600", name, mode)
		}
	}
}

// TestOpenDB_TightensExisting0644 covers the upgrade path: a DB file
// inherited from an older clawpatrol that wrote 0644 should get
// tightened on the next OpenDB.
func TestOpenDB_TightensExisting0644(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "clawpatrol.db")

	// Pre-create with the bad mode, simulating an old install.
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	_ = f.Close()

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	st, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("%s mode = %#o, want 0600 after OpenDB tightens it", dbPath, mode)
	}
}
