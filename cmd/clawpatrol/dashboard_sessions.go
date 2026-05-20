package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// dashboardSessionTokenBytes is the entropy of a session token before
// hex-encoding. 32 bytes = 256 bits = far beyond what an attacker can
// brute-force online, even against a non-rate-limited gate.
const dashboardSessionTokenBytes = 32

// hashSessionToken hashes a raw cookie value with SHA-256 and returns
// the hex representation. The DB never stores the raw token, so a DB
// leak doesn't double as credential leak — the attacker would need
// both the leaked hash AND the matching raw cookie to authenticate.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// createDashboardSession mints a new session for username, persists
// it, and returns the raw cookie value. Caller sets that as the
// cookie value; the DB only holds its SHA-256.
func createDashboardSession(db *sql.DB, username string, ttl time.Duration) (string, error) {
	if db == nil {
		return "", fmt.Errorf("no db")
	}
	if username == "" {
		return "", fmt.Errorf("session: empty username")
	}
	if ttl <= 0 {
		return "", fmt.Errorf("session: non-positive ttl")
	}
	buf := make([]byte, dashboardSessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("session: read random: %w", err)
	}
	token := hex.EncodeToString(buf)
	now := time.Now()
	_, err := db.Exec(
		`INSERT INTO dashboard_sessions (token_hash, username, created_ns, expires_ns, last_seen_ns)
		 VALUES (?, ?, ?, ?, ?)`,
		hashSessionToken(token), username, now.UnixNano(), now.Add(ttl).UnixNano(), now.UnixNano(),
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

// lookupDashboardSession resolves token to a username if the matching
// row exists AND hasn't expired. Bumps last_seen_ns on hit. Expired
// rows are deleted in passing; the lazy delete keeps the table small
// alongside the periodic sweeper.
//
// Returns (username, true, nil) on a live session; ("", false, nil)
// when the token is missing or expired; ("", false, err) on DB
// trouble.
func lookupDashboardSession(db *sql.DB, token string) (string, bool, error) {
	if db == nil {
		return "", false, fmt.Errorf("no db")
	}
	if token == "" {
		return "", false, nil
	}
	hash := hashSessionToken(token)
	var (
		username  string
		expiresNs int64
	)
	err := db.QueryRow(
		`SELECT username, expires_ns FROM dashboard_sessions WHERE token_hash = ?`,
		hash,
	).Scan(&username, &expiresNs)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	now := time.Now()
	if now.UnixNano() >= expiresNs {
		// Lazy expiry: dropping the row makes the next sweep cheaper
		// and rules out any later confusion. Errors are non-fatal —
		// the sweeper will retry.
		_, _ = db.Exec(`DELETE FROM dashboard_sessions WHERE token_hash = ?`, hash)
		return "", false, nil
	}
	_, _ = db.Exec(
		`UPDATE dashboard_sessions SET last_seen_ns = ? WHERE token_hash = ?`,
		now.UnixNano(), hash,
	)
	return username, true, nil
}

// revokeDashboardSession deletes the row matching token. Used by the
// logout endpoint. Idempotent — unknown tokens are a no-op so a
// double-click on Log out doesn't 500.
func revokeDashboardSession(db *sql.DB, token string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	if token == "" {
		return nil
	}
	_, err := db.Exec(`DELETE FROM dashboard_sessions WHERE token_hash = ?`, hashSessionToken(token))
	return err
}

// revokeAllDashboardSessionsFor wipes every session for username.
// Called when the password rotates so existing cookies stop working
// immediately. Belt-and-suspenders alongside the natural TTL.
func revokeAllDashboardSessionsFor(db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	_, err := db.Exec(`DELETE FROM dashboard_sessions WHERE username = ?`, username)
	return err
}

// sweepExpiredDashboardSessions deletes every row whose expires_ns has
// passed. Returns the row count for logging. Cheap with the
// dashboard_sessions_expires_idx index even on long-running gateways.
func sweepExpiredDashboardSessions(db *sql.DB) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("no db")
	}
	res, err := db.Exec(`DELETE FROM dashboard_sessions WHERE expires_ns <= ?`, time.Now().UnixNano())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
