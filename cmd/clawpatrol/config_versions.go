package main

// Persistence for the gateway config version history — the audit trail
// behind `clawpatrol apply` and `clawpatrol config history`. See
// migrations/sqlite/0020_config_versions.sql for the schema rationale.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

// configVersion is one recorded config snapshot.
type configVersion struct {
	ID            int64  `json:"id"`
	Revision      string `json:"revision"`
	SchemaVersion int    `json:"schema_version"`
	Content       []byte `json:"-"`
	AppliedBy     string `json:"applied_by"`
	Note          string `json:"note"`
	AppliedNs     int64  `json:"applied_ns"`
}

// latestConfigVersion returns the most recently applied version. ok is
// false when the table is empty (no apply / boot recorded yet).
func latestConfigVersion(db *sql.DB) (configVersion, bool, error) {
	if db == nil {
		return configVersion{}, false, fmt.Errorf("no db")
	}
	var v configVersion
	err := db.QueryRow(
		`SELECT id, revision, schema_version, content, applied_by, note, applied_ns
		   FROM config_versions
		  ORDER BY id DESC
		  LIMIT 1`,
	).Scan(&v.ID, &v.Revision, &v.SchemaVersion, &v.Content, &v.AppliedBy, &v.Note, &v.AppliedNs)
	if errors.Is(err, sql.ErrNoRows) {
		return configVersion{}, false, nil
	}
	if err != nil {
		return configVersion{}, false, err
	}
	return v, true, nil
}

// listConfigVersions returns up to limit versions, newest first. limit
// <= 0 returns all.
func listConfigVersions(db *sql.DB, limit int) ([]configVersion, error) {
	if db == nil {
		return nil, fmt.Errorf("no db")
	}
	q := `SELECT id, revision, schema_version, applied_by, note, applied_ns
	        FROM config_versions
	       ORDER BY id DESC`
	args := []any{}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []configVersion
	for rows.Next() {
		var v configVersion
		if err := rows.Scan(&v.ID, &v.Revision, &v.SchemaVersion, &v.AppliedBy, &v.Note, &v.AppliedNs); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// recordConfigVersion inserts a new version row unless its revision
// matches the latest (so boot + apply + reload of the same config don't
// pile up duplicates). Returns the revision and whether a row was
// inserted.
func recordConfigVersion(db *sql.DB, content []byte, schemaVersion int, appliedBy, note string) (revision string, inserted bool, err error) {
	if db == nil {
		return "", false, fmt.Errorf("no db")
	}
	revision = revisionForBytes(content)
	latest, ok, err := latestConfigVersion(db)
	if err != nil {
		return "", false, err
	}
	if ok && latest.Revision == revision {
		return revision, false, nil
	}
	_, err = db.Exec(
		`INSERT INTO config_versions (revision, schema_version, content, applied_by, note, applied_ns)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		revision, schemaVersion, content, appliedBy, note, time.Now().UnixNano(),
	)
	if err != nil {
		return "", false, err
	}
	return revision, true, nil
}

// recordBootConfigVersion records the config the gateway loaded at
// startup, so the history begins from the running config rather than
// from the first `apply`. Best-effort: a recording failure must never
// block the gateway from starting. Skipped for directory configs
// (multi-file merges have no single-file byte stream to hash); apply is
// the path for those.
func recordBootConfigVersion(db *sql.DB, cfgPath string, schemaVersion int) {
	fi, err := os.Stat(cfgPath)
	if err != nil || fi.IsDir() {
		return
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		log.Printf("config history: read boot config: %v", err)
		return
	}
	rev, inserted, err := recordConfigVersion(db, raw, schemaVersion, "boot", "")
	if err != nil {
		log.Printf("config history: record boot config: %v", err)
		return
	}
	if inserted {
		log.Printf("config history: recorded boot config revision %s", rev[:min(12, len(rev))])
	}
}
