package main

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
)

// TestPeerAPITokenRoundTrip mints a token, persists it, looks it
// up by its raw value, and confirms the lookup returns the right
// peer IP. Also confirms the raw token is NOT what's stored — only
// the hash, and that the registration IP is pinned on the row.
func TestPeerAPITokenRoundTrip(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	token, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	if got := peerIPForAPIToken(db, token); got != "10.55.0.42" {
		t.Errorf("peerIPForAPIToken = %q, want 10.55.0.42", got)
	}
	if got := peerIPForAPIToken(db, "wrong-token"); got != "" {
		t.Errorf("unknown token resolved to %q, want empty", got)
	}
	var (
		stored string
		v4     sql.NullString
		v6     sql.NullString
	)
	if err := db.QueryRow(
		`SELECT token_hash, approved_ipv4, approved_ipv6 FROM peer_api_tokens WHERE peer_ip = ?`, "10.55.0.42",
	).Scan(&stored, &v4, &v6); err != nil {
		t.Fatalf("select: %v", err)
	}
	if stored == token {
		t.Errorf("DB stored raw token instead of hash")
	}
	if stored != hashPeerAPIToken(token) {
		t.Errorf("stored hash mismatch")
	}
	if !v4.Valid || v4.String != "203.0.113.7" {
		t.Errorf("approved_ipv4 = %q valid=%v, want 203.0.113.7", v4.String, v4.Valid)
	}
	if v6.Valid {
		t.Errorf("approved_ipv6 set unexpectedly: %q", v6.String)
	}
}

// TestForgetPeerAPITokens covers the cleanup path the dashboard's
// revoke-device flow will eventually use.
func TestForgetPeerAPITokens(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	t1, _ := mintAndPersistPeerAPIToken(db, "10.55.0.1", approvedIPs{V4: "203.0.113.1"})
	t2, _ := mintAndPersistPeerAPIToken(db, "10.55.0.1", approvedIPs{V4: "203.0.113.2"})
	t3, _ := mintAndPersistPeerAPIToken(db, "10.55.0.2", approvedIPs{V4: "203.0.113.3"})
	if peerIPForAPIToken(db, t1) == "" || peerIPForAPIToken(db, t2) == "" || peerIPForAPIToken(db, t3) == "" {
		t.Fatal("setup")
	}
	forgetPeerAPITokens(db, "10.55.0.1")
	if peerIPForAPIToken(db, t1) != "" {
		t.Errorf("t1 still resolves after forget")
	}
	if peerIPForAPIToken(db, t2) != "" {
		t.Errorf("t2 still resolves after forget")
	}
	if peerIPForAPIToken(db, t3) != "10.55.0.2" {
		t.Errorf("t3 lost: forget cascaded too far")
	}
}

// TestBearerFromAuthHeader covers the trivial parser.
func TestBearerFromAuthHeader(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Bearer abc123", "abc123"},
		{"bearer abc123", "abc123"},
		{"BEARER xyz", "xyz"},
		{"Bearer  spaced  ", "spaced"},
		{"Basic abc", ""},
		{"", ""},
		{"abc", ""},
	}
	for _, c := range cases {
		if got := bearerFromAuthHeader(c.in); got != c.want {
			t.Errorf("bearerFromAuthHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestClassifyRemoteAddr covers v4 / v6 / bracketed-v6 / bare-host
// forms of net/http's RemoteAddr.
func TestClassifyRemoteAddr(t *testing.T) {
	cases := []struct {
		in   string
		want approvedIPs
	}{
		{"203.0.113.7:54321", approvedIPs{V4: "203.0.113.7"}},
		{"203.0.113.7", approvedIPs{V4: "203.0.113.7"}},
		{"[2001:db8::1]:443", approvedIPs{V6: "2001:db8::1"}},
		{"2001:db8::1", approvedIPs{V6: "2001:db8::1"}},
		// v4-mapped-v6 collapses to v4.
		{"[::ffff:203.0.113.7]:443", approvedIPs{V4: "203.0.113.7"}},
		// non-IP hosts (test harness shorthand, reverse-proxy
		// artefacts) deliberately return empty: a pin that can't be
		// expressed as an IP is no pin at all.
		{"localhost:1234", approvedIPs{}},
		{"", approvedIPs{}},
	}
	for _, c := range cases {
		got := classifyRemoteAddr(c.in)
		if got != c.want {
			t.Errorf("classifyRemoteAddr(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

// fakeWG fakes both the EndpointsByIP lookup and the
// RevokePeerByIP teardown for checkPeerAPIToken tests.
type fakeWG struct {
	mu        sync.Mutex
	endpoints map[string]string
	revoked   []string
}

func (f *fakeWG) EndpointsByIP() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.endpoints))
	for k, v := range f.endpoints {
		out[k] = v
	}
	return out
}

func (f *fakeWG) RevokePeerByIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, ip)
}

// TestCheckPeerAPIToken_PublicDirectMatch covers the bare-public-URL
// path: the host hits the gateway over the open internet (not via
// the tunnel), so RemoteAddr IS the public source. Matching pin →
// allow.
func TestCheckPeerAPIToken_PublicDirectMatch(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	token, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	wg := &fakeWG{}
	got := checkPeerAPIToken(db, token, "203.0.113.7:48391", wg, wg)
	if got != "10.55.0.42" {
		t.Errorf("got peerIP=%q, want 10.55.0.42", got)
	}
	if len(wg.revoked) != 0 {
		t.Errorf("matching IP triggered revoke: %v", wg.revoked)
	}
	if peerIPForAPIToken(db, token) != "10.55.0.42" {
		t.Errorf("token row vanished after successful check")
	}
}

// TestCheckPeerAPIToken_PublicDirectMismatch covers the
// leaked-credential threat: an attacker on the open internet uses
// the stolen token. The gateway sees RemoteAddr = attacker's public
// IP. checkPeerAPIToken must deny, revoke the WG peer, and drop the
// token rows even when the legit peer's WG underlay still matches
// (which is exactly the gap finding 2 of clawpatrol#193 flagged).
func TestCheckPeerAPIToken_PublicDirectMismatch(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	tok1, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	tok2, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Legit peer's WG handshake is still current — its underlay is
	// 203.0.113.7. An attacker who exfiltrated only the bearer (not
	// the WG private key) shows up over the public internet from
	// 198.51.100.9. Comparing the WG underlay alone would still
	// match the pin; comparing the request's RemoteAddr exposes it.
	wg := &fakeWG{endpoints: map[string]string{"10.55.0.42": "203.0.113.7"}}
	got := checkPeerAPIToken(db, tok1, "198.51.100.9:54321", wg, wg)
	if got != "" {
		t.Errorf("mismatch returned peerIP=%q, want empty", got)
	}
	if len(wg.revoked) != 1 || wg.revoked[0] != "10.55.0.42" {
		t.Errorf("expected single revoke for 10.55.0.42, got %v", wg.revoked)
	}
	if peerIPForAPIToken(db, tok1) != "" {
		t.Errorf("tok1 survived mismatch revoke")
	}
	if peerIPForAPIToken(db, tok2) != "" {
		t.Errorf("tok2 (same peer) survived mismatch revoke")
	}
}

// TestCheckPeerAPIToken_WGTunnelMatch covers the whole-machine wg
// case: the CLI's HTTPS to the gateway URL routes via the tunnel,
// so RemoteAddr is the peer's WG /32. requestSourceForPin falls
// through to wireguard-go's underlay endpoint, which matches the
// pin → allow.
func TestCheckPeerAPIToken_WGTunnelMatch(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	token, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	wg := &fakeWG{endpoints: map[string]string{"10.55.0.42": "203.0.113.7"}}
	got := checkPeerAPIToken(db, token, "10.55.0.42:48391", wg, wg)
	if got != "10.55.0.42" {
		t.Errorf("got peerIP=%q, want 10.55.0.42", got)
	}
	if len(wg.revoked) != 0 {
		t.Errorf("matching IP triggered revoke: %v", wg.revoked)
	}
}

// TestCheckPeerAPIToken_WGTunnelMismatch covers the second attacker
// path: attacker reused the WG keypair to bring up a tunnel of
// their own, so they too land at 10.55.0.42 on the gateway side.
// The wireguard-go underlay reflects the most recent handshake,
// which is the attacker's public IP — the pin catches it.
func TestCheckPeerAPIToken_WGTunnelMismatch(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	tok, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	wg := &fakeWG{endpoints: map[string]string{"10.55.0.42": "198.51.100.9"}}
	if got := checkPeerAPIToken(db, tok, "10.55.0.42:54321", wg, wg); got != "" {
		t.Errorf("mismatch returned peerIP=%q, want empty", got)
	}
	if len(wg.revoked) != 1 || wg.revoked[0] != "10.55.0.42" {
		t.Errorf("expected single revoke for 10.55.0.42, got %v", wg.revoked)
	}
}

// TestCheckPeerAPIToken_WGTunnelNoEndpoint covers the case where the
// request hits the gateway through the tunnel but wireguard-go has
// no remembered endpoint for the peer (no handshake completed). We
// can't verify the source — fail closed.
func TestCheckPeerAPIToken_WGTunnelNoEndpoint(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	token, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	wg := &fakeWG{endpoints: map[string]string{}}
	if got := checkPeerAPIToken(db, token, "10.55.0.42:54321", wg, wg); got != "" {
		t.Errorf("got peerIP=%q, want empty (no underlay to compare)", got)
	}
	// No mismatch detection yet — we don't tear the peer down on
	// "can't tell"; we just refuse the call. Revoke fires only on a
	// concrete mismatch.
	if len(wg.revoked) != 0 {
		t.Errorf("ambiguous source triggered revoke: %v", wg.revoked)
	}
	// Token row should still exist.
	if peerIPForAPIToken(db, token) != "10.55.0.42" {
		t.Errorf("token row dropped on ambiguous source")
	}
}

// TestCheckPeerAPIToken_FamilyMismatch covers the security-model
// rule that a v6 request against a v4-only registration is treated
// as a mismatch (and vice versa). Same teardown as a value
// mismatch.
func TestCheckPeerAPIToken_FamilyMismatch(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	tok, err := mintAndPersistPeerAPIToken(db, "10.55.0.42", approvedIPs{V4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	wg := &fakeWG{}
	if got := checkPeerAPIToken(db, tok, "[2001:db8::1]:443", wg, wg); got != "" {
		t.Errorf("family mismatch returned peerIP=%q, want empty", got)
	}
	if len(wg.revoked) != 1 || wg.revoked[0] != "10.55.0.42" {
		t.Errorf("expected revoke for 10.55.0.42, got %v", wg.revoked)
	}
}

// TestCheckPeerAPIToken_UnknownToken covers the empty-token /
// unrecognised-token branch. No revoke; the caller responds 401.
func TestCheckPeerAPIToken_UnknownToken(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	wg := &fakeWG{}
	if got := checkPeerAPIToken(db, "", "203.0.113.7:1", wg, wg); got != "" {
		t.Errorf("empty token resolved to %q", got)
	}
	if got := checkPeerAPIToken(db, "bogus", "203.0.113.7:1", wg, wg); got != "" {
		t.Errorf("unknown token resolved to %q", got)
	}
	if len(wg.revoked) != 0 {
		t.Errorf("unknown token triggered revoke: %v", wg.revoked)
	}
}

// TestCheckPeerAPIToken_UnpinnedRow covers a pre-migration row with
// NULL pin columns. Such rows must be denied — leaving them open
// would defeat the whole feature. The caller's re-approve flow
// inserts a fresh row with a pin.
func TestCheckPeerAPIToken_UnpinnedRow(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	// Bypass mintAndPersistPeerAPIToken to seed a row with neither
	// approved_ipv4 nor approved_ipv6 — exactly what older rows look
	// like after the 0008 migration applies but before any new join
	// flow re-pins the peer.
	tokenHash := hashPeerAPIToken("legacy-token")
	if _, err := db.Exec(
		`INSERT INTO peer_api_tokens (token_hash, peer_ip, created_ns) VALUES (?, ?, ?)`,
		tokenHash, "10.55.0.42", int64(1),
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	wg := &fakeWG{endpoints: map[string]string{"10.55.0.42": "203.0.113.7"}}
	if got := checkPeerAPIToken(db, "legacy-token", "203.0.113.7:1", wg, wg); got != "" {
		t.Errorf("legacy unpinned row returned peerIP=%q, want empty (fail-closed)", got)
	}
	if len(wg.revoked) != 0 {
		t.Errorf("unpinned row triggered revoke: %v", wg.revoked)
	}
}
