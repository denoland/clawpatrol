package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// keyA and keyB are distinct, well-formed 32-byte WireGuard public keys
// rendered as 64-char hex (what normalizeWGPublicKey returns).
const (
	keyA = "abababababababababababababababababababababababababababababababab"
	keyB = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

func newEnrollmentTestGateway(t *testing.T) *Gateway {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{db: db, onboard: newOnboardRegistry(), agents: NewAgentRegistry()}
	if err := g.onboard.Load(db); err != nil {
		t.Fatalf("onboard load: %v", err)
	}
	return g
}

// startEnrollmentTestWGServer starts a real userspace WGServer for tests
// that exercise AddPeer / RevokePeerByIP / PeerStats. The sandbox cannot
// always bind a UDP socket, so the test is skipped (not failed) when the
// device won't start; CI runs it for real.
func startEnrollmentTestWGServer(t *testing.T, g *Gateway) *WGServer {
	t.Helper()
	prevDB := globalDB
	prevWG := globalWG
	globalDB = g.db
	wg, err := StartWGServer(JoinConfig{
		WGSubnetCIDR: "10.55.0.0/24",
		WGListenPort: freeUDPPort(t),
		PublicURL:    "https://gateway.example.com",
	})
	if err != nil {
		globalDB = prevDB
		t.Skipf("WGServer unavailable in this environment: %v", err)
	}
	setWGServer(wg)
	t.Cleanup(func() {
		wg.dev.Close()
		globalWG = prevWG
		globalDB = prevDB
	})
	return wg
}

func wgPeerRowsForIP(t *testing.T, g *Gateway, ip string) int {
	t.Helper()
	var count int
	if err := g.db.QueryRow("SELECT count(*) FROM wg_peers WHERE ip = ?", ip).Scan(&count); err != nil {
		t.Fatalf("count wg_peers: %v", err)
	}
	return count
}

// seedEnrolledPeer inserts an enrolled wg_peers row directly, for tests that
// exercise the store / reconcile path without a live WireGuard device.
func seedEnrolledPeer(t *testing.T, g *Gateway, ip, pub, subject, replacement string) {
	t.Helper()
	if _, err := g.db.Exec(`INSERT INTO wg_peers
		(pubkey, ip, added_ns, enrolled, subject_key, replacement_key,
		 display_name, owner, profile, authorizer_type, authorizer_name, metadata_json)
		VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pub, ip, time.Now().UnixNano(), subject, replacement,
		"agents/x", "system:serviceaccount:agents:agent-runner", "default",
		enrollmentAuthorizerKubernetesTokenRev, "agents", "{}"); err != nil {
		t.Fatalf("seed enrolled peer: %v", err)
	}
}

type fakeEnrollmentAuthorizer struct{ typ, name string }

func (f fakeEnrollmentAuthorizer) Type() string { return f.typ }
func (f fakeEnrollmentAuthorizer) Name() string { return f.name }
func (f fakeEnrollmentAuthorizer) Authorize(context.Context, string, json.RawMessage) (enrollmentIdentity, error) {
	return enrollmentIdentity{}, nil
}

// registerFor drives registerEnrolledPeer with a synthesized identity, the
// way the HTTP handler would after the authorizer ran. Requires a live
// WGServer (AddPeer); callers start one via startEnrollmentTestWGServer.
func registerFor(t *testing.T, g *Gateway, subjectKey, replacementKey, pub string) (enrollmentRegisterResponse, error) {
	t.Helper()
	id := enrollmentIdentity{
		SubjectKey:     subjectKey,
		ReplacementKey: replacementKey,
		DisplayName:    "agents/x",
		Owner:          "system:serviceaccount:agents:agent-runner",
		Profile:        "default",
		Metadata:       map[string]string{"subject": subjectKey},
	}
	auth := fakeEnrollmentAuthorizer{typ: enrollmentAuthorizerKubernetesTokenRev, name: "agents"}
	return g.registerEnrolledPeer(context.Background(), enabledEnrollmentCfg(), auth, id, enrollmentRegisterRequest{
		Transport:          enrollmentTransportWireGuard,
		WireGuardPublicKey: pub,
	})
}

func TestRegisterEnrolledPeerFresh(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)
	resp, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.PeerIP == "" || resp.Transport != enrollmentTransportWireGuard {
		t.Fatalf("unexpected response %+v", resp)
	}
	if resp.APIToken == "" || resp.ServerPublicKey == "" || resp.Endpoint == "" {
		t.Fatalf("response missing fields %+v", resp)
	}
	p, err := g.enrolledPeerByIP(resp.PeerIP)
	if err != nil {
		t.Fatalf("enrolled peer not persisted: %v", err)
	}
	if p.PubKeyHex != keyA {
		t.Fatalf("enrolled pubkey = %q, want %q", p.PubKeyHex, keyA)
	}
	if peerIPForAPIToken(g.db, resp.APIToken) != resp.PeerIP {
		t.Fatal("api token does not resolve to peer ip")
	}
	if g.onboard.ProfileForIP(resp.PeerIP) != "default" {
		t.Fatalf("profile = %q, want default", g.onboard.ProfileForIP(resp.PeerIP))
	}
}

// A sidecar that restarts in place keeps its pod UID but generates a fresh
// WireGuard key. The same subject must reuse its own slot (reuse the IP, swap
// the key) instead of being locked out.
func TestRegisterEnrolledPeerSameSubjectNewKey(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)
	first, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	second, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyB)
	if err != nil {
		t.Fatalf("same-subject key rotation should not conflict: %v", err)
	}
	if second.PeerIP != first.PeerIP {
		t.Fatalf("peer_ip = %q, want reuse of %q", second.PeerIP, first.PeerIP)
	}
	p, err := g.enrolledPeerByIP(second.PeerIP)
	if err != nil {
		t.Fatalf("enrolled peer lookup: %v", err)
	}
	if p.PubKeyHex != keyB {
		t.Fatalf("enrolled pubkey = %q, want rotated key %q", p.PubKeyHex, keyB)
	}
	if got := wgPeerRowsForIP(t, g, second.PeerIP); got != 1 {
		t.Fatalf("wg_peers rows for reused IP = %d, want 1", got)
	}
}

// A different subject presenting a live peer's public key is a conflict.
func TestRegisterEnrolledPeerPublicKeyConflict(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)
	if _, err := registerFor(t, g, "kubernetes:agents:uid-other", "kubernetes:agents:other-pod", keyA); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	_, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if !errors.Is(err, errEnrollmentConflict) {
		t.Fatalf("err = %v, want conflict", err)
	}
}

// A pod recreated under the same name (new UID) retires the prior instance.
// The old instance is torn down before the new one is provisioned, so its
// freed IP may be handed straight back — the takeover is observable in the
// revoked token and the swapped enrollment, not the address.
func TestRegisterEnrolledPeerReplacementTakeover(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)
	old, err := registerFor(t, g, "kubernetes:agents:uid-old", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("seed register: %v", err)
	}
	fresh, err := registerFor(t, g, "kubernetes:agents:uid-new", "kubernetes:agents:agent-1", keyB)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if peerIPForAPIToken(g.db, old.APIToken) != "" {
		t.Fatal("old instance api token should have been revoked")
	}
	peers, err := g.findEnrolledPeers("kubernetes:agents:agent-1", keyB)
	if err != nil {
		t.Fatalf("find enrolled: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("enrolled peers for replacement key = %d, want 1 (old retired)", len(peers))
	}
	if peers[0].SubjectKey != "kubernetes:agents:uid-new" || peers[0].PubKeyHex != keyB {
		t.Fatalf("surviving enrollment = %+v, want the new instance", peers[0])
	}
	if peerIPForAPIToken(g.db, fresh.APIToken) != fresh.PeerIP {
		t.Fatal("new instance api token should resolve")
	}
}

// When persistence fails after the WireGuard peer is provisioned, the
// register path rolls back the transport peer + API token so nothing leaks.
func TestRegisterEnrolledPeerRollbackOnPersistFailure(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)
	// Drop the token table so mintAndPersistPeerAPIToken fails after AddPeer
	// has already provisioned the peer.
	if _, err := g.db.Exec("DROP TABLE peer_api_tokens"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA); err == nil {
		t.Fatal("expected register to fail")
	}
	if n := wgPeerRowsForIP(t, g, "10.55.0.2"); n != 0 {
		t.Fatalf("wg_peers rows after rollback = %d, want 0", n)
	}
}

func TestRegisterEnrolledPeerValidatesResponseBeforeProvisioning(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)
	cfg := enabledEnrollmentCfg()
	cfg.Settings.WireGuard.Endpoint = "missing-port"
	id := enrollmentIdentity{
		SubjectKey:     "kubernetes:agents:uid-1",
		ReplacementKey: "kubernetes:agents:agent-1",
		DisplayName:    "agents/agent-1",
		Owner:          "system:serviceaccount:agents:agent-runner",
		Profile:        "default",
	}
	auth := fakeEnrollmentAuthorizer{typ: enrollmentAuthorizerKubernetesTokenRev, name: "agents"}

	_, err := g.registerEnrolledPeer(context.Background(), cfg, auth, id, enrollmentRegisterRequest{
		Transport:          enrollmentTransportWireGuard,
		WireGuardPublicKey: keyA,
	})
	if err == nil {
		t.Fatal("expected malformed endpoint to reject registration")
	}
	if n := wgPeerRowsForIP(t, g, "10.55.0.2"); n != 0 {
		t.Fatalf("wg_peers rows after response validation failure = %d, want 0", n)
	}
	var tokenCount int
	if err := g.db.QueryRow("SELECT count(*) FROM peer_api_tokens").Scan(&tokenCount); err != nil {
		t.Fatalf("count peer api tokens: %v", err)
	}
	if tokenCount != 0 {
		t.Fatalf("peer api tokens after response validation failure = %d, want 0", tokenCount)
	}
}

func TestAllocateWGPeerPersistsBeforeUnlock(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	wg := startEnrollmentTestWGServer(t, g)
	start := make(chan struct{})
	type result struct {
		ip  string
		err error
	}
	results := make(chan result, 2)
	var workers sync.WaitGroup
	join := enabledEnrollmentCfg().Join()
	for _, pubkey := range []string{keyA, keyB} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			ip, err := wg.allocatePeer(join, pubkey)
			results <- result{ip: ip, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var ips []string
	for result := range results {
		if result.err != nil {
			t.Fatalf("allocate peer: %v", result.err)
		}
		ips = append(ips, result.ip)
	}
	if len(ips) != 2 || ips[0] == ips[1] {
		t.Fatalf("concurrent allocations = %v, want two distinct addresses", ips)
	}
	for _, ip := range ips {
		if got := wgPeerRowsForIP(t, g, ip); got != 1 {
			t.Fatalf("wg_peers rows for %s = %d, want 1", ip, got)
		}
	}
}

func TestAllocateWGPeerFailsClosedOnAllocationReadError(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	wg := startEnrollmentTestWGServer(t, g)
	if _, err := g.db.Exec("DROP TABLE wg_peers"); err != nil {
		t.Fatalf("drop wg_peers: %v", err)
	}
	if _, err := wg.allocatePeer(enabledEnrollmentCfg().Join(), keyA); err == nil {
		t.Fatal("allocation should fail when the persisted allocation set cannot be read")
	}
}

// reapStaleEnrolledPeers revokes an enrolled peer whose receive counter has
// not advanced within its liveness window. We register a real peer, then
// backdate its liveness tracker so the reaper sees no progress past the window.
func TestReapStaleEnrolledPeers(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	g.cfg.Store(enabledEnrollmentCfg())
	g.policy.Store(enabledEnrollmentPolicy(t)) // reaper reads the liveness window from the compiled policy
	startEnrollmentTestWGServer(t, g)
	resp, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Backdate progress well beyond the default 3m TTL with a high lastRx so
	// no real keepalive could have advanced past it during the test.
	g.enrollmentMu.Lock()
	g.enrollLive[keyA] = enrollmentLiveness{lastRx: 1 << 40, lastProgress: time.Now().Add(-time.Hour)}
	g.enrollmentMu.Unlock()

	g.reapStaleEnrolledPeers(context.Background())

	if _, err := g.enrolledPeerByIP(resp.PeerIP); err == nil {
		t.Fatal("stale enrolled peer should have been reaped")
	}
	if peerIPForAPIToken(g.db, resp.APIToken) != "" {
		t.Fatal("reaped peer api token should be revoked")
	}
	if g.onboard.HasDevice(resp.PeerIP) {
		t.Fatal("reaped peer device row should be forgotten")
	}
}

func TestReconcileEnrolledPeersRestoresRuntimeState(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	const ip = "10.55.0.22"
	seedEnrolledPeer(t, g, ip, keyA, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1")

	restored, err := g.reconcileEnrolledPeers(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if restored != 1 {
		t.Fatalf("restored = %d, want 1", restored)
	}
	if !g.onboard.HasDevice(ip) {
		t.Fatal("reconcile should restore device row")
	}
	if got := g.onboard.ProfileForIP(ip); got != "default" {
		t.Fatalf("profile = %q, want default", got)
	}
	if got := g.onboard.OwnerForIP(ip); got != "system:serviceaccount:agents:agent-runner" {
		t.Fatalf("owner = %q, want service account owner", got)
	}
	if got := g.onboard.HostnameForIP(ip); got != "agents/x" {
		t.Fatalf("hostname = %q, want agents/x", got)
	}
	found := false
	for _, agent := range g.agents.snapshot() {
		if agent.IP == ip {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("reconcile should seed agent registry")
	}
	g.enrollmentMu.Lock()
	_, tracked := g.enrollLive[keyA]
	g.enrollmentMu.Unlock()
	if !tracked {
		t.Fatal("reconcile should seed liveness tracking")
	}
}

func TestApiEnrollmentList(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	w := &webMux{g: g}

	seedEnrolledPeer(t, g, "10.55.0.2", keyA, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1")
	seedEnrolledPeer(t, g, "10.55.0.3", keyB, "kubernetes:agents:uid-2", "kubernetes:agents:agent-2")

	postRec := httptest.NewRecorder()
	w.apiEnrollmentList(postRec, httptest.NewRequest(http.MethodPost, "/api/enrollment/peers", nil))
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST -> %d, want 405", postRec.Code)
	}

	rec := httptest.NewRecorder()
	w.apiEnrollmentList(rec, httptest.NewRequest(http.MethodGet, "/api/enrollment/peers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET -> %d, want 200", rec.Code)
	}
	var views []enrolledPeerView
	if err := json.NewDecoder(rec.Body).Decode(&views); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("want 2 enrolled peers, got %d", len(views))
	}
	byIP := map[string]enrolledPeerView{}
	for _, v := range views {
		byIP[v.PeerIP] = v
	}
	one := byIP["10.55.0.2"]
	if one.Profile != "default" || one.PublicKey != keyA {
		t.Fatalf("unexpected view %+v", one)
	}
	if one.DisplayName != "agents/x" || one.AuthorizerType != enrollmentAuthorizerKubernetesTokenRev {
		t.Fatalf("unexpected metadata %+v", one)
	}
	if one.CreatedAt == "" || one.Transport != enrollmentTransportWireGuard {
		t.Fatalf("missing fields %+v", one)
	}
}

// enabledEnrollmentCfg parses the top-level enrollment grammar so
// the returned *config.Gateway has a populated Policy.Enrollments (which is
// what IsEnrollmentEnabled and the runtime lookups read).
const enabledEnrollmentHCL = `gateway {
  public_url = "https://gateway.example.com"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

enrollment "kubernetes_token_review" "agents" {
  audience = "clawpatrol"
  match {
    namespace       = "agents"
    service_account = "agent-runner"
    profile_label   = "clawpatrol.dev/profile"
    profiles        = ["default"]
  }
}

profile "default" { credentials = [] }
`

func enabledEnrollmentCfg() *config.Gateway {
	gw, diags := config.LoadBytes([]byte(enabledEnrollmentHCL), "enabled-enrollment.hcl")
	if diags.HasErrors() {
		panic("enabledEnrollmentCfg: " + diags.Error())
	}
	return gw
}

// enabledEnrollmentPolicy compiles enabledEnrollmentCfg so tests can seed
// g.policy with the compiled enrollment the runtime looks authorizers up in.
func enabledEnrollmentPolicy(t *testing.T) *config.CompiledPolicy {
	t.Helper()
	cp, err := config.Compile(enabledEnrollmentCfg())
	if err != nil {
		t.Fatalf("compile enrollment policy: %v", err)
	}
	return cp
}

func doRegister(w *webMux, method, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, enrollmentRegisterPath, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	w.apiEnrollmentRegister(rec, req)
	return rec
}

func TestApiEnrollmentRegisterGuards(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	g.cfg.Store(enabledEnrollmentCfg())
	g.policy.Store(enabledEnrollmentPolicy(t))
	// Verifier resolves any token to a pod in the "ghost" profile, which is
	// not declared in the policy above.
	g.k8sVerifier = fakeK8sVerifier(func(_ context.Context, _ string, claims k8sEnrollmentClaims, _ *config.CompiledK8sEnrollment) (k8sVerifiedPod, error) {
		return k8sVerifiedPod{
			Namespace:      claims.PodNamespace,
			Name:           claims.PodName,
			UID:            claims.PodUID,
			ServiceAccount: "agent-runner",
			Profile:        "ghost",
		}, nil
	})
	w := &webMux{g: g}

	validBody := `{"transport":"wireguard","authorizer":"agents","wireguard_public_key":"` + keyA + `","claims":{"pod_name":"a","pod_namespace":"agents","pod_uid":"u"}}`

	if rec := doRegister(w, http.MethodGet, "tok", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET -> %d, want 405", rec.Code)
	}
	if rec := doRegister(w, http.MethodPost, "", validBody); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer -> %d, want 401", rec.Code)
	}
	if rec := doRegister(w, http.MethodPost, "tok", "{not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json -> %d, want 400", rec.Code)
	}
	unknownAuthz := `{"transport":"wireguard","authorizer":"nope","wireguard_public_key":"` + keyA + `","claims":{"pod_name":"a","pod_namespace":"agents","pod_uid":"u"}}`
	if rec := doRegister(w, http.MethodPost, "tok", unknownAuthz); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown authorizer -> %d, want 403", rec.Code)
	}
	badTransport := `{"transport":"carrier-pigeon","authorizer":"agents","claims":{}}`
	if rec := doRegister(w, http.MethodPost, "tok", badTransport); rec.Code != http.StatusForbidden {
		t.Fatalf("bad transport -> %d, want 403", rec.Code)
	}
	// Authorize succeeds but the resolved profile is not declared.
	if rec := doRegister(w, http.MethodPost, "tok", validBody); rec.Code != http.StatusForbidden {
		t.Fatalf("undeclared profile -> %d, want 403", rec.Code)
	}

	// Disabled feature hides the endpoint entirely.
	g.cfg.Store(&config.Gateway{Settings: &config.GatewaySettings{WireGuard: &config.WireGuardBlock{}}})
	if rec := doRegister(w, http.MethodPost, "tok", validBody); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled -> %d, want 404", rec.Code)
	}
}

// A regular onboarded peer carrying a peer API token must not be able to
// drive the enrollment delete teardown when it holds no enrollment.
func TestApiEnrollmentDeleteRequiresEnrollment(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	g.cfg.Store(enabledEnrollmentCfg())
	w := &webMux{g: g}

	const ip = "10.55.0.50"
	g.onboard.AssignProfile(ip, "default")
	g.onboard.SetHostname(ip, "regular-device")
	token, err := mintAndPersistPeerAPIToken(g.db, ip)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, enrollmentRegisterPath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	w.apiEnrollmentRegister(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete without enrollment -> %d, want 404", rec.Code)
	}
	if peerIPForAPIToken(g.db, token) != ip {
		t.Fatal("regular peer api token was wrongly revoked")
	}
	if !g.onboard.HasDevice(ip) {
		t.Fatal("regular peer device row was wrongly forgotten")
	}
}

func TestApiEnrollmentDeleteWithEnrollment(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	g.cfg.Store(enabledEnrollmentCfg())
	startEnrollmentTestWGServer(t, g)
	w := &webMux{g: g}

	resp, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, enrollmentRegisterPath, nil)
	req.Header.Set("Authorization", "Bearer "+resp.APIToken)
	rec := httptest.NewRecorder()
	w.apiEnrollmentRegister(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete with enrollment -> %d, want 204", rec.Code)
	}
	if _, err := g.enrolledPeerByIP(resp.PeerIP); err == nil {
		t.Fatal("enrollment should be gone after delete")
	}
	if peerIPForAPIToken(g.db, resp.APIToken) != "" {
		t.Fatal("api token should be revoked after delete")
	}
	if g.onboard.HasDevice(resp.PeerIP) {
		t.Fatal("device row should be forgotten after delete")
	}
}

// TestRegisterEnrolledPeerKeepaliveGating verifies that client keepalive and
// watchdog settings are only returned when the client requests them —
// i.e. the clawpatrol bridge (Keepalive: true), not other enrollment clients.
func TestRegisterEnrolledPeerKeepaliveGating(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)
	auth := fakeEnrollmentAuthorizer{typ: enrollmentAuthorizerKubernetesTokenRev, name: "agents"}
	id := func(uid, name string) enrollmentIdentity {
		return enrollmentIdentity{
			SubjectKey:     "kubernetes:agents:" + uid,
			ReplacementKey: "kubernetes:agents:" + name,
			DisplayName:    "agents/" + name,
			Owner:          "system:serviceaccount:agents:agent-runner",
			Profile:        "default",
		}
	}

	// Bridge: requests keepalive → gateway echoes the derived cadence (the
	// package defaults, since the test policy sets no explicit knobs).
	bridge, err := g.registerEnrolledPeer(context.Background(), enabledEnrollmentCfg(), auth,
		id("uid-bridge", "bridge"), enrollmentRegisterRequest{
			Transport: enrollmentTransportWireGuard, WireGuardPublicKey: keyA, Keepalive: true,
		})
	if err != nil {
		t.Fatalf("bridge register: %v", err)
	}
	wantKA := int(config.EnrollmentDefaultKeepalive.Seconds())
	if bridge.KeepaliveIntervalSeconds != wantKA || bridge.KeepaliveReapCount != config.EnrollmentDefaultReapCount {
		t.Fatalf("bridge keepalive passdown = %ds/%d, want %ds/%d",
			bridge.KeepaliveIntervalSeconds, bridge.KeepaliveReapCount, wantKA, config.EnrollmentDefaultReapCount)
	}

	// Non-bridge: no request flag → no gateway keepalive, no passdown.
	other, err := g.registerEnrolledPeer(context.Background(), enabledEnrollmentCfg(), auth,
		id("uid-other", "other"), enrollmentRegisterRequest{
			Transport: enrollmentTransportWireGuard, WireGuardPublicKey: keyB,
		})
	if err != nil {
		t.Fatalf("non-bridge register: %v", err)
	}
	if other.KeepaliveIntervalSeconds != 0 || other.KeepaliveReapCount != 0 {
		t.Fatalf("non-bridge keepalive passdown = %ds/%d, want 0/0",
			other.KeepaliveIntervalSeconds, other.KeepaliveReapCount)
	}
}
