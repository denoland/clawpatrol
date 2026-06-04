package main

// Persistence for the config state backend — the rows behind
// `clawpatrol apply` and `clawpatrol config history`. See
// migrations/sqlite/0020_config_versions.sql for the schema rationale.
// OSS-Terraform-shaped: a row carries only what conflict detection
// needs (serial=id, content, revision) plus a convenience timestamp.

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// configVersion is one recorded config snapshot.
type configVersion struct {
	ID            int64  `json:"id"`
	Revision      string `json:"revision"`
	SchemaVersion int    `json:"schema_version"`
	Content       []byte `json:"-"`
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
		`SELECT id, revision, schema_version, content, applied_ns
		   FROM config_versions
		  ORDER BY id DESC
		  LIMIT 1`,
	).Scan(&v.ID, &v.Revision, &v.SchemaVersion, &v.Content, &v.AppliedNs)
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
	q := `SELECT id, revision, schema_version, applied_ns
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
	defer func() { _ = rows.Close() }()
	var out []configVersion
	for rows.Next() {
		var v configVersion
		if err := rows.Scan(&v.ID, &v.Revision, &v.SchemaVersion, &v.AppliedNs); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// recordConfigVersion inserts a new version row unless its revision
// matches the latest (so boot + apply + reload of the same config don't
// pile up duplicates). Returns the revision and whether a row was
// inserted. Used for the boot seed; apply uses recordConfigVersionCAS.
func recordConfigVersion(db *sql.DB, content []byte, schemaVersion int) (revision string, inserted bool, err error) {
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
		`INSERT INTO config_versions (revision, schema_version, content, applied_ns)
		 VALUES (?, ?, ?, ?)`,
		revision, schemaVersion, content, time.Now().UnixNano(),
	)
	if err != nil {
		return "", false, err
	}
	return revision, true, nil
}
