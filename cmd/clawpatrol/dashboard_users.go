package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// dashboardUsersBcryptCost is the bcrypt cost used for stored passwords.
// 12 is the current OWASP default — about ~250 ms on a 2024 laptop.
const dashboardUsersBcryptCost = 12

// dashboardRootUsername is the username of the bootstrap operator row.
// Future user-management features may add more rows; the gate today
// only consults this single row.
const dashboardRootUsername = "root"

// lookupDashboardUser returns the stored bcrypt hash for the given
// username. The bool is false when no row exists; the caller is
// expected to treat that as "no auth configured yet" and trigger the
// first-run flow.
func lookupDashboardUser(db *sql.DB, username string) (string, bool, error) {
	if db == nil {
		return "", false, fmt.Errorf("no db")
	}
	var hash string
	err := db.QueryRow(
		`SELECT password_hash FROM dashboard_users WHERE username = ?`,
		username,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// setDashboardUser upserts the row for username with a bcrypt hash of
// password. Used by the first-run web flow and the
// --set-dashboard-password CLI flag.
func setDashboardUser(db *sql.DB, username, password string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), dashboardUsersBcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UnixNano()
	_, err = db.Exec(
		`INSERT INTO dashboard_users (username, password_hash, created_ns, updated_ns)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   password_hash = excluded.password_hash,
		   updated_ns    = excluded.updated_ns`,
		username, string(hash), now, now,
	)
	return err
}

// deleteDashboardUser removes the row for username. Used by
// --reset-dashboard-password. No-op if the row doesn't exist.
func deleteDashboardUser(db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	_, err := db.Exec(`DELETE FROM dashboard_users WHERE username = ?`, username)
	return err
}

// checkDashboardPassword constant-time compares password against the
// stored hash for username. Returns (ok, exists, err) — exists=false
// means there is no row at all (caller should trigger first-run).
func checkDashboardPassword(db *sql.DB, username, password string) (bool, bool, error) {
	hash, ok, err := lookupDashboardUser(db, username)
	if err != nil || !ok {
		return false, ok, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false, true, nil
	}
	return true, true, nil
}
