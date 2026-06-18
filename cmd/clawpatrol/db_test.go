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

// TestCheckDirWritable_OK: a writable dir passes and the probe file is
// cleaned up (it must not be mistaken for real state).
func TestCheckDirWritable_OK(t *testing.T) {
	dir := t.TempDir()
	if err := checkDirWritable(dir); err != nil {
		t.Fatalf("checkDirWritable: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("probe left files behind: %v", entries)
	}
}

// TestCheckDirWritable_ReadOnly is the regression for the root-owned
// /opt/clawpatrol case: MkdirAll no-ops on the existing dir, but the
// unprivileged gateway can't create clawpatrol.db inside it. The
// preflight must catch that with a clear error instead of letting
// sqlite fail later with SQLITE_CANTOPEN(14).
func TestCheckDirWritable_ReadOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Restore write so t.TempDir's cleanup can remove the dir.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := checkDirWritable(dir); err == nil {
		t.Fatal("expected error for read-only state_dir, got nil")
	}
}
