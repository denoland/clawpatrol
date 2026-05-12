package main

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/denoland/clawpatrol/config/plugins/endpoints"
)

// TestStateImportRoundTrip drops every legacy on-disk artifact into a
// scratch directory, runs the importer, and verifies the data lands
// in sqlite and the source files are removed.
func TestStateImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(caDir, "ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Mint a real CA so importLegacyCA's parse step is exercised
	// end-to-end. Reuses ca.go: we read the rows after writing the
	// disk files, check they round-trip.
	caScratch := filepath.Join(dir, "scratch.db")
	scratch, err := OpenDB(caScratch)
	if err != nil {
		t.Fatalf("scratch open: %v", err)
	}
	cc, err := loadOrMintCA(scratch)
	if err != nil {
		t.Fatalf("mint scratch CA: %v", err)
	}
	_ = scratch.Close()
	_ = cc
	var caCert, caKey []byte
	{
		db2, err := OpenDB(caScratch)
		if err != nil {
			t.Fatalf("reopen scratch: %v", err)
		}
		if err := db2.QueryRow(`SELECT cert_pem, key_pem FROM ca_material WHERE id = 1`).
			Scan(&caCert, &caKey); err != nil {
			t.Fatalf("read scratch: %v", err)
		}
		_ = db2.Close()
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt"), caCert, 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.key"), caKey, 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}

	// WG server key.
	wgHex, err := wgGenPrivateHex()
	if err != nil {
		t.Fatalf("wg gen: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "wg-server.key"), []byte(wgHex), 0o600); err != nil {
		t.Fatalf("write wg key: %v", err)
	}

	// Instance ID.
	instanceID := newReqID()
	if err := os.WriteFile(filepath.Join(stateDir, "instance_id"), []byte(instanceID+"\n"), 0o600); err != nil {
		t.Fatalf("write instance_id: %v", err)
	}

	// dnsvip.json.
	dnsvipJSON := []byte(`{
		"version": 1,
		"entries": [{
			"id": 7,
			"hostname": "h.example.com",
			"v4": "10.78.0.7",
			"v6": "fd78::7"
		}]
	}`)
	if err := os.WriteFile(filepath.Join(stateDir, "dnsvip.json"), dnsvipJSON, 0o600); err != nil {
		t.Fatalf("write dnsvip: %v", err)
	}

	// SSH host key: a PEM body is enough; importLegacySSHHostKeys
	// just round-trips the bytes through the blob store.
	sshKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fake ed25519 key bytes")})
	if err := os.WriteFile(filepath.Join(caDir, "ssh", "edge.key"), sshKeyPEM, 0o600); err != nil {
		t.Fatalf("write ssh key: %v", err)
	}

	// Codex JWT keys. Need a JSON blob with the three expected fields
	// so the import sanity check passes.
	codexJSON, _ := json.Marshal(map[string]string{
		"kid":                       "sha256--legacy",
		"rsa_private_pkcs8_b64":     "aGVsbG8=",
		"ed25519_private_pkcs8_b64": "d29ybGQ=",
	})
	codexDir := filepath.Join(dir, "clawpatrol")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	codexPath := filepath.Join(codexDir, "codex_jwt_keys.json")
	if err := os.WriteFile(codexPath, codexJSON, 0o600); err != nil {
		t.Fatalf("write codex: %v", err)
	}
	t.Setenv("CLAWPATROL_DIR", codexDir)

	// Run the importer.
	db, err := OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	blobs := newGatewayBlobStore(db)
	importLegacyState(db, blobs, caDir, stateDir)

	// Assert rows present.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ca_material`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ca_material rows = %d (err %v)", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM wg_server_key`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("wg_server_key rows = %d (err %v)", n, err)
	}
	var gotInstance string
	if err := db.QueryRow(`SELECT instance_id FROM telemetry_state WHERE id = 1`).Scan(&gotInstance); err != nil {
		t.Fatalf("telemetry: %v", err)
	}
	if gotInstance != instanceID {
		t.Fatalf("instance_id = %q want %q", gotInstance, instanceID)
	}
	if err := db.QueryRow(`SELECT count(*) FROM dnsvip_allocations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("dnsvip rows = %d (err %v)", n, err)
	}
	if data, found, err := blobs.Get(endpoints.SSHHostKeyKind, "edge"); err != nil || !found || len(data) == 0 {
		t.Fatalf("ssh host key: found=%v err=%v len=%d", found, err, len(data))
	}
	if data, found, err := blobs.Get(endpoints.CodexJWTKeysKind, ""); err != nil || !found || len(data) == 0 {
		t.Fatalf("codex keys: found=%v err=%v len=%d", found, err, len(data))
	}

	// Assert source files removed.
	for _, p := range []string{
		filepath.Join(caDir, "ca.crt"),
		filepath.Join(caDir, "ca.key"),
		filepath.Join(stateDir, "wg-server.key"),
		filepath.Join(stateDir, "instance_id"),
		filepath.Join(stateDir, "dnsvip.json"),
		filepath.Join(caDir, "ssh", "edge.key"),
		codexPath,
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s removed, stat err = %v", p, err)
		}
	}
}

// TestStateImportIdempotent confirms a second run doesn't error and
// doesn't overwrite the rows it already inserted. We do this by
// pre-populating the destination, dropping the source files, and
// running the importer — the rows should stay exactly as we set them.
func TestStateImportIdempotent(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Plant an existing row.
	want := newReqID()
	if err := importTelemetryInstanceID(db, want); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Drop a stale file claiming a different id.
	if err := os.WriteFile(filepath.Join(stateDir, "instance_id"), []byte("stale-id\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	blobs := newGatewayBlobStore(db)
	importLegacyState(db, blobs, "", stateDir)

	var got string
	if err := db.QueryRow(`SELECT instance_id FROM telemetry_state WHERE id = 1`).Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != want {
		t.Fatalf("import overwrote existing row: got %q want %q", got, want)
	}
	// And since the destination row was non-empty, the stale file
	// should NOT have been deleted — the import is a no-op when the
	// row already exists.
	if _, err := os.Stat(filepath.Join(stateDir, "instance_id")); err != nil {
		t.Errorf("expected stale file to remain (importer skipped); stat err = %v", err)
	}
}

// TestLoadOrMintCAStable confirms a second call returns the same
// material — the row persists across reopens.
func TestLoadOrMintCAStable(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	a, err := loadOrMintCA(db)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	b, err := loadOrMintCA(db)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if a.caCert.SerialNumber.Cmp(b.caCert.SerialNumber) != 0 {
		t.Fatalf("CA drifted: %v -> %v", a.caCert.SerialNumber, b.caCert.SerialNumber)
	}
}

// TestLoadOrGenWGServerKeyStable mirrors the CA test for the WG key.
func TestLoadOrGenWGServerKeyStable(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	a, err := loadOrGenWGServerKey(db)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	b, err := loadOrGenWGServerKey(db)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if a != b {
		t.Fatalf("WG priv drifted: %q -> %q", a, b)
	}
}

// TestLoadOrCreateInstanceIDStable mirrors the CA test for telemetry.
func TestLoadOrCreateInstanceIDStable(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	a, err := loadOrCreateInstanceID(db)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	b, err := loadOrCreateInstanceID(db)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if a != b {
		t.Fatalf("instance id drifted: %q -> %q", a, b)
	}
}

// TestGatewayBlobStoreRoundTrip exercises the sqlite-backed
// BlobStore in isolation — Put then Get returns the same bytes,
// and a non-existent key returns (nil, false, nil).
func TestGatewayBlobStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := newGatewayBlobStore(db)

	if data, found, err := s.Get("kind1", "name1"); err != nil || found || data != nil {
		t.Fatalf("empty get: found=%v err=%v data=%v", found, err, data)
	}
	if err := s.Put("kind1", "name1", []byte("hello")); err != nil {
		t.Fatalf("put: %v", err)
	}
	data, found, err := s.Get("kind1", "name1")
	if err != nil || !found || string(data) != "hello" {
		t.Fatalf("get back: data=%q found=%v err=%v", data, found, err)
	}
	// Overwrite.
	if err := s.Put("kind1", "name1", []byte("world")); err != nil {
		t.Fatalf("put 2: %v", err)
	}
	data, found, err = s.Get("kind1", "name1")
	if err != nil || !found || string(data) != "world" {
		t.Fatalf("overwrite: data=%q found=%v err=%v", data, found, err)
	}
}
