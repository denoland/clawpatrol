package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestSeedAgentsFromDevices_PopulatesRegistry covers the happy path:
// every devices.id row gets fed into the agent registry on boot.
// Regression guard for the prior pattern in runGateway where rows were
// opened in an `if` block with `defer rows.Close()` — Go binds defer to
// the enclosing function, so the rows handle (and its pooled
// connection) stayed open for the gateway's entire lifetime instead
// of returning promptly. Extracting the loop into seedAgentsFromDevices
// scoped the defer to a real return; this test pins that contract.
func TestSeedAgentsFromDevices_PopulatesRegistry(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	want := []string{"10.55.0.7", "10.55.0.8", "10.55.0.9"}
	for _, ip := range want {
		if _, err := db.Exec(
			`INSERT INTO devices (id, created_ns) VALUES (?, ?)`,
			ip, time.Now().UnixNano(),
		); err != nil {
			t.Fatalf("seed device %s: %v", ip, err)
		}
	}

	reg := NewAgentRegistry()
	if err := seedAgentsFromDevices(db, reg); err != nil {
		t.Fatalf("seedAgentsFromDevices: %v", err)
	}

	reg.mu.RLock()
	got := make(map[string]bool, len(reg.agents))
	for ip := range reg.agents {
		got[ip] = true
	}
	reg.mu.RUnlock()

	for _, ip := range want {
		if !got[ip] {
			t.Errorf("agent for %s not seeded", ip)
		}
	}

	// Confirm the connection-pool fingerprint is back at idle once the
	// helper returns. The bug we are guarding against would leave one
	// connection bound to the open *sql.Rows; with the defer scoped to
	// the helper's own frame, Stats().InUse must drop back to 0.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if db.Stats().InUse == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := db.Stats().InUse; n != 0 {
		t.Errorf("db.InUse = %d after seed; rows handle leaked", n)
	}
}

// TestSeedAgentsFromDevices_EmptyTable: registry stays empty, helper
// reports no error.
func TestSeedAgentsFromDevices_EmptyTable(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	reg := NewAgentRegistry()
	if err := seedAgentsFromDevices(db, reg); err != nil {
		t.Fatalf("seedAgentsFromDevices: %v", err)
	}
	reg.mu.RLock()
	n := len(reg.agents)
	reg.mu.RUnlock()
	if n != 0 {
		t.Errorf("registry has %d agents, want 0", n)
	}
}

// TestSeedAgentsFromDevices_QueryError surfaces the underlying error
// instead of swallowing it. Triggered here by closing the DB before
// the call so Query fails immediately.
func TestSeedAgentsFromDevices_QueryError(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_ = db.Close()

	reg := NewAgentRegistry()
	if err := seedAgentsFromDevices(db, reg); err == nil {
		t.Fatalf("seedAgentsFromDevices returned nil error on closed DB")
	}
}
