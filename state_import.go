package main

// Legacy-state import. Before 0008_gateway_state, the gateway
// scattered six small pieces of state across the filesystem next to
// its sqlite db (CA cert+key, WG server key, per-endpoint SSH host
// keys, codex JWT keys, telemetry instance id, dnsvip allocations).
// On first boot of a migrated gateway this importer reads any of
// those files that still exist, writes their contents into sqlite,
// and deletes the originals.
//
// Each artifact is independent: a failure on one (missing file,
// permission error, parse failure) doesn't block the others, and the
// import is idempotent — it only runs against an empty destination
// row, so a partial import on boot N resumes cleanly on boot N+1.
// Once every artifact has migrated, the importer is a no-op.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/denoland/clawpatrol/config/plugins/endpoints"
)

// importLegacyState moves any pre-sqlite on-disk state into the DB
// and removes the source files. Errors are logged but never fatal —
// the gateway can always fall back to minting fresh material.
func importLegacyState(db *sql.DB, blobs *gatewayBlobStore, caDir, stateDir string) {
	importLegacyCA(db, caDir)
	importLegacyWGKey(db, stateDir)
	importLegacyInstanceID(db, stateDir)
	importLegacyDNSVIP(db, stateDir)
	importLegacySSHHostKeys(blobs, caDir)
	importLegacyCodexJWTKeys(blobs)
}

func importLegacyCA(db *sql.DB, caDir string) {
	if caDir == "" {
		return
	}
	if hasRow(db, `SELECT 1 FROM ca_material WHERE id = 1`) {
		return
	}
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist) {
		return
	}
	if certErr != nil {
		log.Printf("import: ca.crt: %v", certErr)
		return
	}
	if keyErr != nil {
		log.Printf("import: ca.key: %v", keyErr)
		return
	}
	if err := importCAFromPEM(db, certPEM, keyPEM); err != nil {
		log.Printf("import: ca insert: %v", err)
		return
	}
	log.Printf("import: ca.crt + ca.key → ca_material; removing %s", caDir)
	_ = os.Remove(certPath)
	_ = os.Remove(keyPath)
}

func importLegacyWGKey(db *sql.DB, stateDir string) {
	if stateDir == "" {
		return
	}
	if hasRow(db, `SELECT 1 FROM wg_server_key WHERE id = 1`) {
		return
	}
	path := filepath.Join(stateDir, "wg-server.key")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("import: wg-server.key: %v", err)
		return
	}
	if err := importWGServerKey(db, string(data)); err != nil {
		log.Printf("import: wg key insert: %v", err)
		return
	}
	log.Printf("import: wg-server.key → wg_server_key")
	_ = os.Remove(path)
}

func importLegacyInstanceID(db *sql.DB, stateDir string) {
	if stateDir == "" {
		return
	}
	if hasRow(db, `SELECT 1 FROM telemetry_state WHERE id = 1`) {
		return
	}
	path := filepath.Join(stateDir, "instance_id")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("import: instance_id: %v", err)
		return
	}
	if err := importTelemetryInstanceID(db, string(data)); err != nil {
		log.Printf("import: instance_id insert: %v", err)
		return
	}
	log.Printf("import: instance_id → telemetry_state")
	_ = os.Remove(path)
}

// legacyDNSVIPFile mirrors the old persistFile shape in dnsvip.go
// (kept here because dnsvip no longer needs JSON serialization).
type legacyDNSVIPFile struct {
	Version int                 `json:"version"`
	Entries []legacyDNSVIPEntry `json:"entries"`
}

type legacyDNSVIPEntry struct {
	ID       uint32     `json:"id"`
	Hostname string     `json:"hostname"`
	V4       netip.Addr `json:"v4"`
	V6       netip.Addr `json:"v6"`
}

func importLegacyDNSVIP(db *sql.DB, stateDir string) {
	if stateDir == "" {
		return
	}
	if hasRow(db, `SELECT 1 FROM dnsvip_allocations LIMIT 1`) {
		return
	}
	path := filepath.Join(stateDir, "dnsvip.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("import: dnsvip.json: %v", err)
		return
	}
	var f legacyDNSVIPFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("import: dnsvip.json parse: %v", err)
		return
	}
	tx, err := db.Begin()
	if err != nil {
		log.Printf("import: dnsvip tx: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range f.Entries {
		if !e.V4.IsValid() || !e.V6.IsValid() || e.Hostname == "" {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO dnsvip_allocations (id, hostname, v4, v6) VALUES (?, ?, ?, ?)`,
			e.ID, e.Hostname, e.V4.String(), e.V6.String(),
		); err != nil {
			log.Printf("import: dnsvip insert %q: %v", e.Hostname, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("import: dnsvip commit: %v", err)
		return
	}
	log.Printf("import: dnsvip.json (%d entries) → dnsvip_allocations", len(f.Entries))
	_ = os.Remove(path)
}

func importLegacySSHHostKeys(blobs *gatewayBlobStore, caDir string) {
	if caDir == "" || blobs == nil {
		return
	}
	sshDir := filepath.Join(caDir, "ssh")
	entries, err := os.ReadDir(sshDir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("import: read %s: %v", sshDir, err)
		return
	}
	var imported, kept int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		endpointName := strings.TrimSuffix(e.Name(), ".key")
		// Skip if the blob already exists — this is the idempotency
		// guard for partial re-runs.
		if _, found, err := blobs.Get(endpoints.SSHHostKeyKind, endpointName); err == nil && found {
			kept++
			continue
		}
		path := filepath.Join(sshDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("import: read %s: %v", path, err)
			continue
		}
		if err := blobs.Put(endpoints.SSHHostKeyKind, endpointName, data); err != nil {
			log.Printf("import: ssh host key %q: %v", endpointName, err)
			continue
		}
		_ = os.Remove(path)
		imported++
	}
	if imported > 0 {
		log.Printf("import: %d ssh host key(s) → gateway_blobs", imported)
	}
	if imported > 0 || kept == 0 {
		// Drop the now-empty ssh/ directory. os.Remove fails harmless-
		// ly if it's non-empty (e.g. a stray .DS_Store), which is the
		// behavior we want.
		_ = os.Remove(sshDir)
	}
}

func importLegacyCodexJWTKeys(blobs *gatewayBlobStore) {
	if blobs == nil {
		return
	}
	if _, found, err := blobs.Get(endpoints.CodexJWTKeysKind, ""); err == nil && found {
		return
	}
	// codex_jwt_keys.json lived under $CLAWPATROL_DIR or
	// ~/.clawpatrol — same path resolution the old plugin used.
	path := codexLegacyJWTKeysPath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("import: codex_jwt_keys.json: %v", err)
		return
	}
	// Sanity check: it's JSON and has the three expected fields.
	var probe struct {
		KID                string `json:"kid"`
		RSAPrivatePKCS8B64 string `json:"rsa_private_pkcs8_b64"`
		Ed25519PKCS8B64    string `json:"ed25519_private_pkcs8_b64"`
	}
	if err := json.Unmarshal(data, &probe); err != nil || probe.KID == "" {
		log.Printf("import: codex_jwt_keys.json malformed; skipping")
		return
	}
	if err := blobs.Put(endpoints.CodexJWTKeysKind, "", data); err != nil {
		log.Printf("import: codex jwt keys put: %v", err)
		return
	}
	log.Printf("import: codex_jwt_keys.json → gateway_blobs")
	_ = os.Remove(path)
}

// codexLegacyJWTKeysPath mirrors the path resolution the old codex
// endpoint plugin used: $CLAWPATROL_DIR if set, else ~/.clawpatrol.
func codexLegacyJWTKeysPath() string {
	if d := os.Getenv("CLAWPATROL_DIR"); d != "" {
		return filepath.Join(d, "codex_jwt_keys.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".clawpatrol", "codex_jwt_keys.json")
}

// hasRow returns true when the given SELECT yields at least one row.
// Used by import helpers as the "destination already populated" guard
// so a re-run on a partially-migrated gateway is a no-op.
func hasRow(db *sql.DB, query string, args ...any) bool {
	row := db.QueryRow(query, args...)
	var one int
	err := row.Scan(&one)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		log.Printf("import: %q: %v", query, err)
		return false
	}
	return true
}
