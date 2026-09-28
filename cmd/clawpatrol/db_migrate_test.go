package main

import (
	"database/sql"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// migrationFiles returns the embedded migrations sorted by number.
func migrationFiles(t *testing.T) []struct {
	num  int
	name string
} {
	t.Helper()
	entries, err := fs.ReadDir(migrationsFS, migrationsDir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var out []struct {
		num  int
		name string
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		i := strings.IndexAny(e.Name(), "_-")
		n, err := strconv.Atoi(e.Name()[:max(i, 0)])
		if i <= 0 || err != nil {
			t.Fatalf("migration %s does not start with a number", e.Name())
		}
		out = append(out, struct {
			num  int
			name string
		}{n, e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].num < out[j].num })
	return out
}

// Two migrations with one number break upgrades: a database already at that
// version skips the second file. This happens when branches that each add a
// migration are merged.
func TestMigrationNumbersAreUnique(t *testing.T) {
	seen := map[int]string{}
	for _, m := range migrationFiles(t) {
		if prev, ok := seen[m.num]; ok {
			t.Fatalf("migrations %s and %s share number %d; renumber the newer one", prev, m.name, m.num)
		}
		seen[m.num] = m.name
	}
}

// A database created by the previous release, which has every migration
// but the newest ones, upgrades to the current schema.
func TestMigrateUpgradesExistingDatabase(t *testing.T) {
	files := migrationFiles(t)
	latest := files[len(files)-1].num
	enrollment := -1
	for _, m := range files {
		if strings.Contains(m.name, "wg_peer_enrollment") {
			enrollment = m.num
		}
	}
	if enrollment < 0 {
		t.Fatal("wg_peer_enrollment migration not found")
	}

	// Stop right before the enrollment migration, like a gateway that ran a
	// release without enrollment.
	old := fstest.MapFS{}
	for _, m := range files {
		if m.num >= enrollment {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, migrationsDir+"/"+m.name)
		if err != nil {
			t.Fatalf("read %s: %v", m.name, err)
		}
		old[migrationsDir+"/"+m.name] = &fstest.MapFile{Data: body}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "upgrade.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := migrateFS(db, old); err != nil {
		t.Fatalf("migrate to the previous release: %v", err)
	}
	if got := schemaVersion(t, db); got >= enrollment {
		t.Fatalf("previous release schema = %d, want < %d", got, enrollment)
	}

	if err := migrate(db); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if got := schemaVersion(t, db); got != latest {
		t.Fatalf("schema after upgrade = %d, want %d", got, latest)
	}
	if _, err := db.Exec(`SELECT enrolled, subject_key, replacement_key, metadata_json FROM wg_peers LIMIT 1`); err != nil {
		t.Fatalf("enrollment columns missing after upgrade: %v", err)
	}
}

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM _schema`).Scan(&v); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	return v
}
