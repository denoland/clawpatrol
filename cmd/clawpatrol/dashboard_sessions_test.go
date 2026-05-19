package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func newSessionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCreateAndLookupDashboardSession(t *testing.T) {
	db := newSessionTestDB(t)
	token, err := createDashboardSession(db, "root", time.Hour)
	if err != nil {
		t.Fatalf("createDashboardSession: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	user, ok, err := lookupDashboardSession(db, token)
	if err != nil {
		t.Fatalf("lookupDashboardSession: %v", err)
	}
	if !ok || user != "root" {
		t.Fatalf("lookup = (%q, %v), want (root, true)", user, ok)
	}
}

func TestLookupDashboardSessionUnknownToken(t *testing.T) {
	db := newSessionTestDB(t)
	user, ok, err := lookupDashboardSession(db, "deadbeef")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok || user != "" {
		t.Fatalf("unknown token returned (%q, %v), want (\"\", false)", user, ok)
	}
}

func TestLookupDashboardSessionEmptyToken(t *testing.T) {
	db := newSessionTestDB(t)
	user, ok, err := lookupDashboardSession(db, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok || user != "" {
		t.Fatalf("empty token returned (%q, %v), want (\"\", false)", user, ok)
	}
}

func TestRevokeDashboardSession(t *testing.T) {
	db := newSessionTestDB(t)
	token, err := createDashboardSession(db, "root", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := revokeDashboardSession(db, token); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	user, ok, _ := lookupDashboardSession(db, token)
	if ok || user != "" {
		t.Fatalf("revoked token still valid: (%q, %v)", user, ok)
	}

	// Idempotent: a second revoke of the same token is a no-op.
	if err := revokeDashboardSession(db, token); err != nil {
		t.Fatalf("double revoke: %v", err)
	}
}

// TestLookupDashboardSessionLazyExpiry covers the path where a row
// exists but its expires_ns has passed. The lookup must report
// (false, false, nil) AND drop the row in passing.
func TestLookupDashboardSessionLazyExpiry(t *testing.T) {
	db := newSessionTestDB(t)
	token, err := createDashboardSession(db, "root", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Backdate the row so it's already expired.
	if _, err := db.Exec(
		`UPDATE dashboard_sessions SET expires_ns = ? WHERE token_hash = ?`,
		time.Now().Add(-time.Minute).UnixNano(), hashSessionToken(token),
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	user, ok, err := lookupDashboardSession(db, token)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if ok || user != "" {
		t.Fatalf("expired session returned (%q, %v), want (\"\", false)", user, ok)
	}
	// Row should be gone after lazy expiry.
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM dashboard_sessions WHERE token_hash = ?`,
		hashSessionToken(token),
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("expired row not deleted: count = %d", n)
	}
}

func TestRevokeAllDashboardSessionsFor(t *testing.T) {
	db := newSessionTestDB(t)
	t1, _ := createDashboardSession(db, "root", time.Hour)
	t2, _ := createDashboardSession(db, "root", time.Hour)
	tOther, _ := createDashboardSession(db, "other", time.Hour)

	if err := revokeAllDashboardSessionsFor(db, "root"); err != nil {
		t.Fatalf("revoke all: %v", err)
	}

	for _, tok := range []string{t1, t2} {
		if _, ok, _ := lookupDashboardSession(db, tok); ok {
			t.Fatalf("root token survived bulk revoke")
		}
	}
	// Sessions for other users are untouched.
	if user, ok, _ := lookupDashboardSession(db, tOther); !ok || user != "other" {
		t.Fatalf("non-root session was collaterally revoked: (%q, %v)", user, ok)
	}
}

// TestSetDashboardUserRevokesExistingSessions: rotating the password
// must invalidate every live session for that user without waiting
// for the TTL.
func TestSetDashboardUserRevokesExistingSessions(t *testing.T) {
	db := newSessionTestDB(t)
	if err := setDashboardUser(db, "root", "initial-password-1234"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	token, err := createDashboardSession(db, "root", time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	if err := setDashboardUser(db, "root", "rotated-password-5678"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if _, ok, _ := lookupDashboardSession(db, token); ok {
		t.Fatal("session survived password rotation")
	}
}

func TestSweepExpiredDashboardSessions(t *testing.T) {
	db := newSessionTestDB(t)
	live, _ := createDashboardSession(db, "root", time.Hour)
	expired, _ := createDashboardSession(db, "root", time.Hour)
	// Backdate one.
	if _, err := db.Exec(
		`UPDATE dashboard_sessions SET expires_ns = ? WHERE token_hash = ?`,
		time.Now().Add(-time.Minute).UnixNano(), hashSessionToken(expired),
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	n, err := sweepExpiredDashboardSessions(db)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("sweep deleted %d rows, want 1", n)
	}

	if _, ok, _ := lookupDashboardSession(db, live); !ok {
		t.Fatal("live session collateral-deleted by sweep")
	}
}
