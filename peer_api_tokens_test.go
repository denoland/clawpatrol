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
		// non-IP host falls into V4 slot (loopback hostname forms
		// land here under net/http/httptest harnesses).
		{"localhost:1234", approvedIPs{V4: "localhost"}},
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

// TestCheckPeerAPIToken_Match covers the happy path: token is known,
// WG underlay matches the pinned v4. Token survives, no revoke.
func TestCheckPeerAPIToken_Match(t *testing.T) {
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
	got := checkPeerAPIToken(db, token, "ignored", wg, wg)
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

// TestCheckPeerAPIToken_NoEndpointYet covers the boot race: the WG
// device hasn't surfaced an endpoint for the peer (the first request
// can land before wireguard-go's IpcGet has been updated). The
// pinning check must defer rather than tear the tunnel down on the
// first call.
func TestCheckPeerAPIToken_NoEndpointYet(t *testing.T) {
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
	got := checkPeerAPIToken(db, token, "ignored", wg, wg)
	if got != "10.55.0.42" {
		t.Errorf("got peerIP=%q, want 10.55.0.42 (deferred pin)", got)
	}
	if len(wg.revoked) != 0 {
		t.Errorf("missing endpoint triggered revoke: %v", wg.revoked)
	}
}

// TestCheckPeerAPIToken_Mismatch covers the leaked-credential case:
// token presents from a deviating underlay v4. checkPeerAPIToken
// must (a) refuse the call, (b) revoke the WG peer, (c) drop every
// token row for that peer.
func TestCheckPeerAPIToken_Mismatch(t *testing.T) {
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
	// Underlay endpoint is a different public IP — attacker on
	// another network presenting the stolen credential.
	wg := &fakeWG{endpoints: map[string]string{"10.55.0.42": "198.51.100.9"}}
	if got := checkPeerAPIToken(db, tok1, "ignored", wg, wg); got != "" {
		t.Errorf("mismatch returned peerIP=%q, want empty", got)
	}
	if len(wg.revoked) != 1 || wg.revoked[0] != "10.55.0.42" {
		t.Errorf("expected single revoke for 10.55.0.42, got %v", wg.revoked)
	}
	// Both tokens for the peer must be gone — restoring access
	// requires re-approval in the dashboard.
	if peerIPForAPIToken(db, tok1) != "" {
		t.Errorf("tok1 survived mismatch revoke")
	}
	if peerIPForAPIToken(db, tok2) != "" {
		t.Errorf("tok2 (same peer) survived mismatch revoke")
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
	wg := &fakeWG{endpoints: map[string]string{"10.55.0.42": "2001:db8::1"}}
	if got := checkPeerAPIToken(db, tok, "ignored", wg, wg); got != "" {
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
	if got := checkPeerAPIToken(db, "", "ignored", wg, wg); got != "" {
		t.Errorf("empty token resolved to %q", got)
	}
	if got := checkPeerAPIToken(db, "bogus", "ignored", wg, wg); got != "" {
		t.Errorf("unknown token resolved to %q", got)
	}
	if len(wg.revoked) != 0 {
		t.Errorf("unknown token triggered revoke: %v", wg.revoked)
	}
}
