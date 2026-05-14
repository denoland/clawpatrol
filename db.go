package main

// SQLite-backed persistent state. Replaces the per-blob JSON files
// (oauth-*.json, onboarded.json, wg-peers.json, gateway.log JSONL)
// with a single ${state_dir}/clawpatrol.db.
//
// Schema lives in migrations/sqlite/, applied in numbered order on
// every boot. The _schema table tracks the highest version applied;
// migrations <= that number are skipped. Pattern mirrors
// ../unclaw/src/migrations.ts.
//
// Driver: modernc.org/sqlite — pure Go, keeps CGO_ENABLED=0 builds
// working so cross-compilation + the `-trimpath -ldflags='-s -w'`
// release recipe stay unchanged.

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/sqlite/*.sql
var migrationsFS embed.FS

// OpenDB opens (or creates) the SQLite store at path, applies any
// pending migrations, and returns a *sql.DB ready for shared use
// across modules. WAL mode + a generous busy_timeout let many readers
// + a single writer coexist without the Sink goroutine and the
// dashboard editor stepping on each other.
func OpenDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}
	// Tighten file modes after the sqlite driver creates them. The
	// driver creates files at process-umask (commonly 0644), but the
	// DB holds the CA private key, OAuth tokens, and audit log —
	// owner-only is the only correct mode. Idempotent: catches both
	// fresh creates and existing files inherited from older installs.
	// Mitigates security-review F-24.
	tightenDBPerms(path)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// tightenDBPerms chmods the sqlite db file plus its WAL/SHM
// sidecars to 0600. Called after sql.Open + db.Ping. Missing files
// are skipped (the WAL/SHM may not exist yet on fresh boots). Any
// chmod failure is logged but doesn't block startup — the
// warnIfStateLooselyPermissioned tripwire in main.go logs a follow-
// up warning if the mode doesn't stick.
func tightenDBPerms(dbPath string) {
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		err := os.Chmod(p, 0o600)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		log.Printf("warning: chmod %s 0600: %v", p, err)
	}
}

// migrate applies any unapplied .sql files from migrations/sqlite/.
// File names must start with a zero-padded number (0001_*, 0002_*),
// applied in ascending order.
func migrate(db *sql.DB) error {
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS _schema (version INTEGER NOT NULL)"); err != nil {
		return err
	}
	current := 0
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM _schema").Scan(&current); err != nil {
		return err
	}
	files, err := fs.ReadDir(migrationsFS, "migrations/sqlite")
	if err != nil {
		return err
	}
	type m struct {
		num  int
		name string
	}
	pending := []m{}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		i := strings.IndexAny(f.Name(), "_-")
		if i <= 0 {
			continue
		}
		n, err := strconv.Atoi(f.Name()[:i])
		if err != nil {
			continue
		}
		if n <= current {
			continue
		}
		pending = append(pending, m{num: n, name: f.Name()})
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].num < pending[j].num })
	for _, p := range pending {
		body, err := fs.ReadFile(migrationsFS, "migrations/sqlite/"+p.name)
		if err != nil {
			return err
		}
		if _, err := db.Exec(string(body)); err != nil {
			return fmt.Errorf("%s: %w", p.name, err)
		}
		// Migration files MAY insert their own _schema row (0001
		// does, since it's the first to run). Catch-all here for
		// later migrations that don't.
		var have int
		if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM _schema").Scan(&have); err != nil {
			return err
		}
		if have < p.num {
			if _, err := db.Exec("INSERT INTO _schema (version) VALUES (?)", p.num); err != nil {
				return err
			}
		}
		log.Printf("[migrate] applied %s", p.name)
	}
	return nil
}
