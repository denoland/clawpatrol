package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

const (
	enrollmentRegisterPath                 = "/api/enrollment/register"
	enrollmentTransportWireGuard           = "wireguard"
	enrollmentAuthorizerKubernetesTokenRev = "kubernetes_token_review"
	enrollmentDefaultMTU                   = 1420
	// enrollmentReaperInterval is how often the reaper wakes to sample each
	// enrolled peer's WireGuard rx and revoke peers past their liveness
	// window.
	enrollmentReaperInterval = 20 * time.Second
	// enrollmentDefaultLiveness is the fallback WireGuard-quiet grace
	// window used only when a peer's authorizer can no longer be resolved
	// (e.g. removed from the policy on reload) — orphaned peers still get
	// reaped.
	enrollmentDefaultLiveness = 75 * time.Second
)

type enrollmentRegisterRequest struct {
	Transport          string          `json:"transport"`
	Authorizer         string          `json:"authorizer"`
	WireGuardPublicKey string          `json:"wireguard_public_key,omitempty"`
	Claims             json.RawMessage `json:"claims,omitempty"`
	// Keepalive is set by resident tunnel hosts (clawpatrol bridge) that run
	// a liveness watchdog. It asks the gateway to return the authorizer's
	// resolved keepalive interval and reap count so the client can configure
	// its tunnel and recovery thresholds.
	Keepalive bool `json:"keepalive,omitempty"`
}

type enrollmentRegisterResponse struct {
	Transport       string   `json:"transport"`
	PeerIP          string   `json:"peer_ip"`
	PeerIPv6        string   `json:"peer_ipv6"`
	ServerPublicKey string   `json:"server_public_key"`
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	MTU             int      `json:"mtu"`
	APIToken        string   `json:"api_token"`
	CAPEM           string   `json:"ca_pem,omitempty"`
	// KeepaliveIntervalSeconds is the persistent-keepalive interval the
	// sidecar applies to its tunnel.
	KeepaliveIntervalSeconds int `json:"keepalive_interval_s,omitempty"`
	// KeepaliveReapCount is how many missed keepalives the gateway waits
	// before reaping; the sidecar sizes its watchdog rekey/reconnect
	// escalation from it. 0 disables reaping and the sidecar's self-heal.
	KeepaliveReapCount int `json:"keepalive_reap_count,omitempty"`
	// GatewayTunnelIP is the gateway's address inside the WireGuard subnet.
	// The sidecar sends ICMP echo to it as its bidirectional liveness probe:
	// a reply proves both directions of the tunnel in one round trip.
	GatewayTunnelIP string `json:"gateway_tunnel_ip,omitempty"`
}

// enrollmentIdentity is the normalized identity an authorizer returns
// after verifying a workload. Profile is server-derived (e.g. from a Pod
// label), never submitted by the client.
type enrollmentIdentity struct {
	SubjectKey     string
	ReplacementKey string
	DisplayName    string
	Owner          string
	Profile        string
	Metadata       map[string]string
}

type enrollmentAuthorizer interface {
	Type() string
	Name() string
	Authorize(ctx context.Context, token string, claims json.RawMessage) (enrollmentIdentity, error)
}

// enrolledPeer is the enrollment metadata stored alongside a WireGuard
// peer in the wg_peers table (enrolled=1). There is no separate lease
// table; liveness is observed from the WG device (rx_bytes progress), so
// there is no stored expiry.
type enrolledPeer struct {
	PeerIP         string
	PubKeyHex      string
	SubjectKey     string
	ReplacementKey string
	DisplayName    string
	Owner          string
	Profile        string
	AuthorizerType string
	AuthorizerName string
	MetadataJSON   string
	AddedNS        int64
}

// enrollmentLiveness tracks per-peer WireGuard receive progress so the
// reaper can revoke peers whose tunnel has gone quiet past its liveness window.
type enrollmentLiveness struct {
	lastRx       uint64
	lastProgress time.Time
}

// enrolledPeerView is the dashboard/API shape of an enrolled peer.
type enrolledPeerView struct {
	PeerIP         string            `json:"peer_ip"`
	Transport      string            `json:"transport"`
	AuthorizerType string            `json:"authorizer_type"`
	AuthorizerName string            `json:"authorizer_name"`
	SubjectKey     string            `json:"subject_key"`
	DisplayName    string            `json:"display_name"`
	Owner          string            `json:"owner"`
	Profile        string            `json:"profile"`
	PublicKey      string            `json:"public_key,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      string            `json:"created_at"`
	LastHandshake  string            `json:"last_handshake,omitempty"`

	// Liveness surface for the dashboard.
	KeepaliveIntervalSeconds int    `json:"keepalive_interval_seconds,omitempty"`
	ReapCount                int    `json:"reap_count,omitempty"`
	LastRxAt                 string `json:"last_rx_at,omitempty"`
}

var errEnrollmentConflict = errors.New("enrollment conflict")

func (w *webMux) apiEnrollmentRegister(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(rw, "POST or DELETE", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodDelete {
		w.apiEnrollmentDelete(rw, r)
		return
	}
	cfg := w.g.cfg.Load()
	if cfg == nil || !cfg.IsEnrollmentEnabled() {
		http.NotFound(rw, r)
		return
	}
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	if token == "" {
		http.Error(rw, "missing bearer token", http.StatusUnauthorized)
		return
	}
	var req enrollmentRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(rw, "bad json", http.StatusBadRequest)
		return
	}
	authorizer, err := w.g.enrollmentAuthorizerFor(cfg, req.Transport, req.Authorizer)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	identity, err := authorizer.Authorize(r.Context(), token, req.Claims)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	if err := w.g.enrollmentProfileExists(identity.Profile); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	resp, err := w.g.registerEnrolledPeer(r.Context(), cfg, authorizer, identity, req)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errEnrollmentConflict) {
			status = http.StatusConflict
		}
		http.Error(rw, err.Error(), status)
		return
	}
	writeJSON(rw, resp)
}

func (w *webMux) apiEnrollmentDelete(rw http.ResponseWriter, r *http.Request) {
	cfg := w.g.cfg.Load()
	if cfg == nil || !cfg.IsEnrollmentEnabled() {
		http.NotFound(rw, r)
		return
	}
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	peerIP := peerIPForAPIToken(w.g.db, token)
	if peerIP == "" {
		http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
		return
	}
	w.g.enrollmentMu.Lock()
	defer w.g.enrollmentMu.Unlock()
	// Only a peer that actually holds an enrollment may drive this teardown.
	// A regular onboarded device can also carry a peer API token; without
	// this guard it could revoke its own WireGuard peer + forget its device
	// row by hitting the enrollment delete path.
	if _, err := w.g.enrolledPeerByIP(peerIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(rw, r)
		} else {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if err := w.g.cleanupEnrolledPeerLocked(context.Background(), peerIP); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// apiEnrollmentList lists every enrolled peer for operator observability.
// Not gated on the feature flag — peers can still be draining after the
// feature is turned off, and an empty list is a fine answer.
func (w *webMux) apiEnrollmentList(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, http.MethodGet, http.StatusMethodNotAllowed)
		return
	}
	views, err := w.g.listEnrolledPeerViews()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, views)
}

func (g *Gateway) listEnrolledPeerViews() ([]enrolledPeerView, error) {
	peers, err := g.listEnrolledPeers()
	if err != nil {
		return nil, err
	}
	var stats map[string]wgDevPeerStat
	if globalWG != nil {
		stats = globalWG.PeerStats()
	}
	policy := g.Policy()

	// Read-only snapshot of the reaper-maintained liveness trackers. The
	// reaper is the sole writer of enrollLive (sampled on its own loop); we
	// only copy lastProgress out, so the critical section is a handful of
	// map lookups with no I/O held under the lock.
	live := make(map[string]time.Time, len(peers))
	g.enrollmentMu.Lock()
	for _, p := range peers {
		if l, ok := g.enrollLive[p.PubKeyHex]; ok {
			live[p.PubKeyHex] = l.lastProgress
		}
	}
	g.enrollmentMu.Unlock()

	views := make([]enrolledPeerView, 0, len(peers))
	for _, p := range peers {
		keepalive, reapCount := enrollmentKeepaliveConfig(policy, p.AuthorizerName)
		v := enrolledPeerView{
			PeerIP:                   p.PeerIP,
			Transport:                enrollmentTransportWireGuard,
			AuthorizerType:           p.AuthorizerType,
			AuthorizerName:           p.AuthorizerName,
			SubjectKey:               p.SubjectKey,
			DisplayName:              p.DisplayName,
			Owner:                    p.Owner,
			Profile:                  p.Profile,
			PublicKey:                p.PubKeyHex,
			CreatedAt:                time.Unix(0, p.AddedNS).UTC().Format(time.RFC3339Nano),
			KeepaliveIntervalSeconds: int(keepalive.Seconds()),
			ReapCount:                reapCount,
		}
		if lp, ok := live[p.PubKeyHex]; ok && !lp.IsZero() {
			v.LastRxAt = lp.UTC().Format(time.RFC3339Nano)
		}
		if p.MetadataJSON != "" && p.MetadataJSON != "{}" {
			_ = json.Unmarshal([]byte(p.MetadataJSON), &v.Metadata)
		}
		if st, ok := stats[p.PubKeyHex]; ok && !st.lastHandshake.IsZero() {
			v.LastHandshake = st.lastHandshake.UTC().Format(time.RFC3339Nano)
		}
		views = append(views, v)
	}
	return views, nil
}

func (g *Gateway) enrollmentAuthorizerFor(cfg *config.Gateway, transport, name string) (enrollmentAuthorizer, error) {
	if strings.TrimSpace(transport) != enrollmentTransportWireGuard {
		return nil, fmt.Errorf("unsupported enrollment transport %q", transport)
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("enrollment authorizer is required")
	}
	if cfg == nil || !cfg.IsEnrollmentEnabled() {
		return nil, fmt.Errorf("enrollment is not enabled")
	}
	// Authorizers resolve from the compiled policy — the same place every
	// other compiled runtime shape is read from — not the raw HCL.
	policy := g.Policy()
	if policy == nil {
		return nil, fmt.Errorf("policy not loaded")
	}
	enrollment := policy.EnrollmentsByName[name]
	if enrollment == nil {
		return nil, fmt.Errorf("enrollment authorizer %q is not configured", name)
	}
	switch enrollment.Type {
	case enrollmentAuthorizerKubernetesTokenRev:
		enr, ok := enrollment.Body.(*config.CompiledK8sEnrollment)
		if !ok {
			return nil, fmt.Errorf("enrollment authorizer %q has unexpected compiled body %T", name, enrollment.Body)
		}
		return &kubernetesTokenReviewAuthorizer{
			name:     enrollment.Name,
			enr:      enr,
			verifier: g.k8sVerifier,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported enrollment authorizer type %q", enrollment.Type)
	}
}

func (g *Gateway) enrollmentProfileExists(profile string) error {
	if profile == "" {
		return fmt.Errorf("enrollment profile is empty")
	}
	policy := g.Policy()
	if policy == nil {
		return fmt.Errorf("policy not loaded")
	}
	if _, ok := policy.Profiles[profile]; !ok {
		return fmt.Errorf("profile %q is not declared", profile)
	}
	return nil
}

// registerEnrolledPeer provisions (or reuses) a WireGuard peer for a
// verified identity and records the enrollment on its wg_peers row.
func (g *Gateway) registerEnrolledPeer(ctx context.Context, cfg *config.Gateway, authorizer enrollmentAuthorizer, identity enrollmentIdentity, req enrollmentRegisterRequest) (enrollmentRegisterResponse, error) {
	pubHex, err := normalizeWGPublicKey(req.WireGuardPublicKey)
	if err != nil {
		return enrollmentRegisterResponse{}, err
	}
	if identity.SubjectKey == "" || identity.ReplacementKey == "" || identity.Profile == "" {
		return enrollmentRegisterResponse{}, fmt.Errorf("enrollment authorizer returned incomplete identity")
	}
	if globalWG == nil {
		return enrollmentRegisterResponse{}, fmt.Errorf("wireguard server not started")
	}
	join := cfg.Join()
	serverPubHex, err := globalWG.PublicKey()
	if err != nil {
		return enrollmentRegisterResponse{}, fmt.Errorf("wg server pub: %w", err)
	}
	serverPubB64, err := hexToB64(serverPubHex)
	if err != nil {
		return enrollmentRegisterResponse{}, err
	}
	endpoint, err := wgClientEndpoint(join.WGEndpoint, join.PublicURL, join.WGListenPort)
	if err != nil {
		return enrollmentRegisterResponse{}, err
	}
	metaJSON := "{}"
	if len(identity.Metadata) > 0 {
		meta, err := json.Marshal(identity.Metadata)
		if err != nil {
			return enrollmentRegisterResponse{}, err
		}
		metaJSON = string(meta)
	}

	g.enrollmentMu.Lock()
	defer g.enrollmentMu.Unlock()

	existing, err := g.findEnrolledPeers(identity.ReplacementKey, pubHex)
	if err != nil {
		return enrollmentRegisterResponse{}, err
	}
	var reuseIP string
	for _, p := range existing {
		switch {
		case p.SubjectKey == identity.SubjectKey:
			// Same authenticated subject (e.g. a sidecar that restarted with
			// a fresh key): reuse its IP, let AddPeer swap the key.
			reuseIP = p.PeerIP
		case p.ReplacementKey == identity.ReplacementKey:
			// Same logical workload, new instance (pod recreated under the
			// same name with a new UID): retire the old instance.
			if err := g.cleanupEnrolledPeerLocked(ctx, p.PeerIP); err != nil {
				return enrollmentRegisterResponse{}, err
			}
		case p.PubKeyHex == pubHex:
			// A different subject is holding this public key.
			return enrollmentRegisterResponse{}, fmt.Errorf("%w: wireguard public key is already registered to another enrolled peer", errEnrollmentConflict)
		}
	}

	peerIP := reuseIP
	if peerIP == "" {
		peerIP, err = globalWG.allocatePeer(join, pubHex)
		if err != nil {
			return enrollmentRegisterResponse{}, fmt.Errorf("wg allocate peer: %w", err)
		}
	} else if err := globalWG.AddPeer(pubHex, peerIP); err != nil {
		return enrollmentRegisterResponse{}, fmt.Errorf("wg add peer: %w", err)
	}
	peerAddr, err := netip.ParseAddr(peerIP)
	if err != nil {
		return enrollmentRegisterResponse{}, fmt.Errorf("invalid allocated peer IP %q: %w", peerIP, err)
	}
	// The client (clawpatrol bridge) is the sole authoritative keepalive
	// sender. The gateway does NOT keepalive back: wireguard-go rearms the
	// persistent-keepalive timer on any authenticated packet — including
	// received ones — so with both sides sending, one direction's traffic
	// perpetually postpones the other's keepalive, and a healthy idle peer can
	// show flat rx in one direction and be falsely reaped.
	var keepalive time.Duration
	var reapCount int
	if req.Keepalive {
		keepalive, reapCount = enrollmentKeepaliveConfig(g.Policy(), authorizer.Name())
	}
	// Roll back the transport peer + token on any failure before the
	// enrollment row is committed.
	committed := false
	defer func() {
		if !committed {
			globalWG.RevokePeerByIP(peerIP)
			if err := deletePeerAPITokensForIP(g.db, peerIP); err != nil {
				log.Printf("enrollment: rollback peer api tokens for %s: %v", peerIP, err)
			}
		}
	}()

	if err := deletePeerAPITokensForIP(g.db, peerIP); err != nil {
		return enrollmentRegisterResponse{}, err
	}
	apiToken, err := mintAndPersistPeerAPIToken(g.db, peerIP)
	if err != nil {
		return enrollmentRegisterResponse{}, err
	}

	resp := enrollmentRegisterResponse{
		Transport:       enrollmentTransportWireGuard,
		PeerIP:          peerIP,
		PeerIPv6:        wg6FromV4(peerAddr).String(),
		ServerPublicKey: serverPubB64,
		Endpoint:        endpoint,
		AllowedIPs:      []string{"0.0.0.0/0", "::/0"},
		MTU:             enrollmentDefaultMTU,
		APIToken:        apiToken,

		KeepaliveIntervalSeconds: int(keepalive.Seconds()),
		KeepaliveReapCount:       reapCount,
		GatewayTunnelIP:          globalWG.GatewayTunnelIP().String(),
	}
	if g.certs != nil {
		resp.CAPEM = string(g.certs.CertPEM())
	}
	if err := markEnrolledPeer(g.db, enrolledPeer{
		PeerIP:         peerIP,
		PubKeyHex:      pubHex,
		SubjectKey:     identity.SubjectKey,
		ReplacementKey: identity.ReplacementKey,
		DisplayName:    identity.DisplayName,
		Owner:          identity.Owner,
		Profile:        identity.Profile,
		AuthorizerType: authorizer.Type(),
		AuthorizerName: authorizer.Name(),
		MetadataJSON:   metaJSON,
	}); err != nil {
		return enrollmentRegisterResponse{}, err
	}
	committed = true
	g.noteEnrolledLiveLocked(pubHex)

	log.Printf("enrollment: registered peer ip=%s name=%q subject=%s authorizer=%s reused_ip=%t",
		peerIP, identity.DisplayName, identity.SubjectKey, authorizer.Name(), reuseIP != "")
	if g.onboard != nil {
		g.onboard.AssignProfile(peerIP, identity.Profile)
		g.onboard.SetOwner(peerIP, identity.Owner)
		g.onboard.SetHostname(peerIP, identity.DisplayName)
	}
	if g.agents != nil {
		g.agents.Seed(peerIP)
	}
	return resp, nil
}

// --- enrollment store (wg_peers, enrolled=1) ---------------------------

const enrolledPeerCols = `pubkey, ip, subject_key, replacement_key, display_name, owner, profile, authorizer_type, authorizer_name, metadata_json, added_ns`

func scanEnrolledPeer(s interface{ Scan(...any) error }) (enrolledPeer, error) {
	var (
		p                                                                 enrolledPeer
		subject, replacement, display, owner, profile, authT, authN, meta sql.NullString
	)
	if err := s.Scan(&p.PubKeyHex, &p.PeerIP, &subject, &replacement, &display, &owner, &profile, &authT, &authN, &meta, &p.AddedNS); err != nil {
		return enrolledPeer{}, err
	}
	p.SubjectKey, p.ReplacementKey, p.DisplayName = subject.String, replacement.String, display.String
	p.Owner, p.Profile = owner.String, profile.String
	p.AuthorizerType, p.AuthorizerName = authT.String, authN.String
	p.MetadataJSON = meta.String
	return p, nil
}

func (g *Gateway) findEnrolledPeers(replacementKey, pubHex string) ([]enrolledPeer, error) {
	rows, err := g.db.Query(`SELECT `+enrolledPeerCols+` FROM wg_peers
		WHERE enrolled = 1 AND (replacement_key = ? OR pubkey = ?)`, replacementKey, pubHex)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []enrolledPeer
	for rows.Next() {
		p, err := scanEnrolledPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (g *Gateway) enrolledPeerByIP(peerIP string) (enrolledPeer, error) {
	return scanEnrolledPeer(g.db.QueryRow(`SELECT `+enrolledPeerCols+` FROM wg_peers
		WHERE ip = ? AND enrolled = 1`, peerIP))
}

func (g *Gateway) listEnrolledPeers() ([]enrolledPeer, error) {
	rows, err := g.db.Query(`SELECT ` + enrolledPeerCols + ` FROM wg_peers WHERE enrolled = 1 ORDER BY added_ns DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []enrolledPeer{}
	for rows.Next() {
		p, err := scanEnrolledPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// markEnrolledPeer stamps enrollment metadata onto the wg_peers row that
// AddPeer just created/updated for pubHex.
func markEnrolledPeer(db *sql.DB, p enrolledPeer) error {
	if p.MetadataJSON == "" {
		p.MetadataJSON = "{}"
	}
	res, err := db.Exec(`UPDATE wg_peers SET
		enrolled = 1, subject_key = ?, replacement_key = ?, display_name = ?,
		owner = ?, profile = ?, authorizer_type = ?, authorizer_name = ?, metadata_json = ?
		WHERE pubkey = ?`,
		p.SubjectKey, p.ReplacementKey, p.DisplayName, p.Owner, p.Profile,
		p.AuthorizerType, p.AuthorizerName, p.MetadataJSON, p.PubKeyHex)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("wg_peers row for pubkey not found")
	}
	return nil
}

// cleanupEnrolledPeerLocked revokes the WireGuard peer (which also deletes
// its wg_peers row, clearing the enrollment), its API tokens, and its
// device/agent registry entries. Caller holds enrollmentMu.
func (g *Gateway) cleanupEnrolledPeerLocked(_ context.Context, peerIP string) error {
	if peerIP == "" {
		return nil
	}
	p, _ := g.enrolledPeerByIP(peerIP)
	// Revoke the bearer first. If that fails, leave the peer intact so the
	// caller can report/retry cleanup without creating an authorized token
	// whose peer and registry records have already disappeared.
	if err := deletePeerAPITokensForIP(g.db, peerIP); err != nil {
		return err
	}
	if globalWG != nil {
		globalWG.RevokePeerByIP(peerIP) // removes the wg_peers row too
	}
	if g.onboard != nil {
		g.onboard.ForgetIP(peerIP)
	}
	if g.agents != nil {
		g.agents.Delete(peerIP)
	}
	if p.PubKeyHex != "" && g.enrollLive != nil {
		delete(g.enrollLive, p.PubKeyHex)
	}
	return nil
}

// --- liveness reaper ---------------------------------------------------

func (g *Gateway) noteEnrolledLiveLocked(pubHex string) {
	if g.enrollLive == nil {
		g.enrollLive = map[string]enrollmentLiveness{}
	}
	g.enrollLive[pubHex] = enrollmentLiveness{lastProgress: time.Now()}
}

// enrollmentLivenessTimeout resolves the WireGuard-quiet grace window for an
// enrolled peer from its authorizer's derived liveness window.
func enrollmentLivenessTimeout(policy *config.CompiledPolicy, authorizerName string) time.Duration {
	if policy != nil && authorizerName != "" {
		if enrollment := policy.EnrollmentsByName[authorizerName]; enrollment != nil {
			return enrollment.Liveness.LivenessWindow() // derived; 0 == reaping disabled
		}
	}
	return enrollmentDefaultLiveness
}

// enrollmentKeepaliveConfig resolves the WireGuard persistent-keepalive
// interval and the missed-keepalive reap count for an authorizer.
func enrollmentKeepaliveConfig(policy *config.CompiledPolicy, authorizerName string) (time.Duration, int) {
	if policy != nil && authorizerName != "" {
		if enrollment := policy.EnrollmentsByName[authorizerName]; enrollment != nil {
			return enrollment.Liveness.KeepaliveInterval, enrollment.Liveness.ReapCount
		}
	}
	return config.EnrollmentDefaultKeepalive, config.EnrollmentDefaultReapCount
}

func (g *Gateway) startEnrollmentReaper(ctx context.Context) {
	ticker := time.NewTicker(enrollmentReaperInterval)
	defer ticker.Stop()
	for {
		g.reapStaleEnrolledPeers(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// reapStaleEnrolledPeers revokes enrolled peers whose WireGuard receive
// counter has not advanced within its authorizer's liveness window
// (keepalive_interval * keepalive_reap_count). A freshly enrolled peer
// gets a full liveness window before it is eligible.
func (g *Gateway) reapStaleEnrolledPeers(_ context.Context) {
	if g == nil || g.db == nil || globalWG == nil {
		return
	}
	policy := g.Policy()
	// PeerStats (a wireguard-go UAPI dump) is identity-independent liveness
	// data, so reading a slightly stale snapshot outside the lock is safe —
	// at worst it delays a reap by one tick, and a peer that's new since the
	// snapshot is seeded fresh below rather than mis-reaped.
	stats := globalWG.PeerStats()

	g.enrollmentMu.Lock()
	defer g.enrollmentMu.Unlock()

	peers, err := g.listEnrolledPeers()
	if err != nil {
		return
	}
	now := time.Now()
	if g.enrollLive == nil {
		g.enrollLive = map[string]enrollmentLiveness{}
	}
	// Observe rx progress: seed newly seen peers with a full grace window
	// (lastProgress = now), advance lastProgress whenever a peer's rx has
	// moved since the last sample, and drop trackers for peers that are
	// gone.
	seen := make(map[string]bool, len(peers))
	for _, p := range peers {
		seen[p.PubKeyHex] = true
		st, ok := stats[p.PubKeyHex]
		live, tracked := g.enrollLive[p.PubKeyHex]
		switch {
		case !tracked:
			rx := uint64(0)
			if ok {
				rx = st.rxBytes
			}
			g.enrollLive[p.PubKeyHex] = enrollmentLiveness{lastRx: rx, lastProgress: now}
		case ok && st.rxBytes > live.lastRx:
			g.enrollLive[p.PubKeyHex] = enrollmentLiveness{lastRx: st.rxBytes, lastProgress: now}
		}
	}
	for pub := range g.enrollLive {
		if !seen[pub] {
			delete(g.enrollLive, pub)
		}
	}
	// Reap peers whose rx has been quiet past their liveness window.
	var stale []string
	for _, p := range peers {
		live := g.enrollLive[p.PubKeyHex]
		// A non-positive window means reaping is disabled for this
		// authorizer (keepalive_reap_count = 0) — never reap.
		if to := enrollmentLivenessTimeout(policy, p.AuthorizerName); to > 0 && now.Sub(live.lastProgress) > to {
			// The gateway's view of a lost peer: one line per real death (a
			// healthy peer never crosses the full window), with how long its
			// WG rx was quiet. Correlates with the sidecar's exit/re-enroll.
			log.Printf("enrollment: reaping peer ip=%s name=%q subject=%s authorizer=%s: no WG rx for %s (> %s)",
				p.PeerIP, p.DisplayName, p.SubjectKey, p.AuthorizerName, now.Sub(live.lastProgress).Round(time.Second), to)
			stale = append(stale, p.PeerIP)
		}
	}
	for _, ip := range stale {
		if err := g.cleanupEnrolledPeerLocked(context.Background(), ip); err != nil {
			log.Printf("enrollment: reap cleanup for %s: %v", ip, err)
		}
	}
}

// --- restart reconcile -------------------------------------------------

// reconcileEnrolledPeers restores the onboard/agent registry view for
// persisted enrolled peers after a gateway restart (the WireGuard device's
// trie is rebuilt from wg_peers by loadPeers) and seeds liveness tracking
// with a fresh grace window.
func (g *Gateway) reconcileEnrolledPeers(_ context.Context) (int, error) {
	if g == nil || g.db == nil {
		return 0, nil
	}
	peers, err := g.listEnrolledPeers()
	if err != nil {
		return 0, err
	}
	if len(peers) == 0 {
		return 0, nil
	}
	g.enrollmentMu.Lock()
	defer g.enrollmentMu.Unlock()
	if g.enrollLive == nil {
		g.enrollLive = map[string]enrollmentLiveness{}
	}
	now := time.Now()
	for _, p := range peers {
		if g.onboard != nil {
			g.onboard.AssignProfile(p.PeerIP, p.Profile)
			g.onboard.SetOwner(p.PeerIP, p.Owner)
			g.onboard.SetHostname(p.PeerIP, p.DisplayName)
		}
		if g.agents != nil {
			g.agents.Seed(p.PeerIP)
		}
		g.enrollLive[p.PubKeyHex] = enrollmentLiveness{lastProgress: now}
	}
	return len(peers), nil
}

func (g *Gateway) logEnrollmentReconcile(ctx context.Context) {
	restored, err := g.reconcileEnrolledPeers(ctx)
	if err != nil {
		log.Printf("enrollment: restoring persisted peers: %v", err)
		return
	}
	if restored > 0 {
		log.Printf("enrollment: restored %d persisted peer(s)", restored)
	}
}

func normalizeWGPublicKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("wireguard_public_key is required")
	}
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 32 {
			return strings.ToLower(s), nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("wireguard_public_key must be a 32-byte WireGuard public key in base64 or hex")
	}
	return hex.EncodeToString(b), nil
}

// --- kubernetes_token_review authorizer --------------------------------

type k8sEnrollmentClaims struct {
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`
	PodUID       string `json:"pod_uid"`
	NodeName     string `json:"node_name"`
}

type k8sVerifiedPod struct {
	Namespace      string
	Name           string
	UID            string
	ServiceAccount string
	Profile        string
	NodeName       string
}

type k8sRegistrationVerifier interface {
	VerifyPod(ctx context.Context, token string, claims k8sEnrollmentClaims, enr *config.CompiledK8sEnrollment) (k8sVerifiedPod, error)
}

type kubernetesTokenReviewAuthorizer struct {
	name     string
	enr      *config.CompiledK8sEnrollment
	verifier k8sRegistrationVerifier
}

func (a *kubernetesTokenReviewAuthorizer) Type() string {
	return enrollmentAuthorizerKubernetesTokenRev
}
func (a *kubernetesTokenReviewAuthorizer) Name() string { return a.name }

func (a *kubernetesTokenReviewAuthorizer) Authorize(ctx context.Context, token string, claims json.RawMessage) (enrollmentIdentity, error) {
	var parsed k8sEnrollmentClaims
	if len(claims) == 0 {
		return enrollmentIdentity{}, fmt.Errorf("claims are required")
	}
	if err := json.Unmarshal(claims, &parsed); err != nil {
		return enrollmentIdentity{}, fmt.Errorf("claims decode: %w", err)
	}
	if parsed.PodName == "" || parsed.PodNamespace == "" || parsed.PodUID == "" {
		return enrollmentIdentity{}, fmt.Errorf("pod_name, pod_namespace, and pod_uid are required")
	}
	verifier := a.verifier
	if verifier == nil {
		v, err := newInClusterK8sClient()
		if err != nil {
			return enrollmentIdentity{}, err
		}
		verifier = v
	}
	pod, err := verifier.VerifyPod(ctx, token, parsed, a.enr)
	if err != nil {
		return enrollmentIdentity{}, err
	}
	displayName := pod.Namespace + "/" + pod.Name
	owner := "system:serviceaccount:" + pod.Namespace + ":" + pod.ServiceAccount
	return enrollmentIdentity{
		SubjectKey:     "kubernetes:" + pod.Namespace + ":" + pod.UID,
		ReplacementKey: "kubernetes:" + pod.Namespace + ":" + pod.Name,
		DisplayName:    displayName,
		Owner:          owner,
		Profile:        pod.Profile,
		Metadata: map[string]string{
			"pod_namespace":   pod.Namespace,
			"pod_name":        pod.Name,
			"pod_uid":         pod.UID,
			"service_account": pod.ServiceAccount,
			"node_name":       pod.NodeName,
		},
	}, nil
}

type inClusterK8sClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func newInClusterK8sClient() (*inClusterK8sClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("kubernetes service environment is not available")
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("read gateway serviceaccount token: %w", err)
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
		roots.AppendCertsFromPEM(ca)
	}
	return &inClusterK8sClient{
		baseURL: "https://" + net.JoinHostPort(host, port),
		token:   strings.TrimSpace(string(token)),
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots},
			},
		},
	}, nil
}

func (c *inClusterK8sClient) VerifyPod(ctx context.Context, token string, claims k8sEnrollmentClaims, enr *config.CompiledK8sEnrollment) (k8sVerifiedPod, error) {
	if enr == nil {
		return k8sVerifiedPod{}, fmt.Errorf("enrollment authorizer is not configured")
	}
	user, err := c.tokenReview(ctx, token, enr.Audience)
	if err != nil {
		return k8sVerifiedPod{}, err
	}
	tokenPodName, ok := singleTokenReviewExtra(user.Extra, "authentication.kubernetes.io/pod-name")
	if !ok {
		return k8sVerifiedPod{}, fmt.Errorf("token is not bound to a pod name")
	}
	tokenPodUID, ok := singleTokenReviewExtra(user.Extra, "authentication.kubernetes.io/pod-uid")
	if !ok {
		return k8sVerifiedPod{}, fmt.Errorf("token is not bound to a pod UID")
	}
	if tokenPodName != claims.PodName || tokenPodUID != claims.PodUID {
		return k8sVerifiedPod{}, fmt.Errorf("token pod binding does not match submitted pod")
	}
	ns, sa, ok := serviceAccountFromUsername(user.Username)
	if !ok {
		return k8sVerifiedPod{}, fmt.Errorf("token is not a serviceaccount token")
	}
	if ns != claims.PodNamespace {
		return k8sVerifiedPod{}, fmt.Errorf("token namespace does not match pod_namespace")
	}
	pod, err := c.getPod(ctx, claims.PodNamespace, claims.PodName)
	if err != nil {
		return k8sVerifiedPod{}, err
	}
	if pod.UID != claims.PodUID {
		return k8sVerifiedPod{}, fmt.Errorf("pod UID mismatch")
	}
	if pod.ServiceAccountName != sa {
		return k8sVerifiedPod{}, fmt.Errorf("token serviceaccount does not match pod serviceaccount")
	}
	profile, err := k8sResolveProfile(enr, ns, sa, pod.Labels)
	if err != nil {
		return k8sVerifiedPod{}, err
	}
	return k8sVerifiedPod{
		Namespace:      claims.PodNamespace,
		Name:           claims.PodName,
		UID:            claims.PodUID,
		ServiceAccount: sa,
		Profile:        profile,
		NodeName:       pod.NodeName,
	}, nil
}

type tokenReviewUser struct {
	Username string
	Extra    map[string][]string
}

func (c *inClusterK8sClient) tokenReview(ctx context.Context, podToken, audience string) (tokenReviewUser, error) {
	if strings.TrimSpace(audience) == "" {
		return tokenReviewUser{}, fmt.Errorf("tokenreview audience is required")
	}
	body := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec": map[string]any{
			"token":     podToken,
			"audiences": []string{audience},
		},
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return tokenReviewUser{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/apis/authentication.k8s.io/v1/tokenreviews", &buf)
	if err != nil {
		return tokenReviewUser{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return tokenReviewUser{}, fmt.Errorf("tokenreview: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tokenReviewUser{}, fmt.Errorf("tokenreview status %d", resp.StatusCode)
	}
	var out struct {
		Status struct {
			Authenticated bool `json:"authenticated"`
			User          struct {
				Username string              `json:"username"`
				Extra    map[string][]string `json:"extra"`
			} `json:"user"`
			Audiences []string `json:"audiences"`
			Error     string   `json:"error"`
		} `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return tokenReviewUser{}, fmt.Errorf("tokenreview decode: %w", err)
	}
	if !out.Status.Authenticated {
		if out.Status.Error != "" {
			return tokenReviewUser{}, fmt.Errorf("tokenreview rejected token: %s", out.Status.Error)
		}
		return tokenReviewUser{}, fmt.Errorf("tokenreview rejected token")
	}
	if !slices.Contains(out.Status.Audiences, audience) {
		return tokenReviewUser{}, fmt.Errorf("tokenreview response does not include audience %q", audience)
	}
	return tokenReviewUser{
		Username: out.Status.User.Username,
		Extra:    out.Status.User.Extra,
	}, nil
}

func singleTokenReviewExtra(extra map[string][]string, key string) (string, bool) {
	values := extra[key]
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

type k8sPodInfo struct {
	UID                string
	Labels             map[string]string
	ServiceAccountName string
	NodeName           string
}

func (c *inClusterK8sClient) getPod(ctx context.Context, namespace, name string) (k8sPodInfo, error) {
	url := c.baseURL + "/api/v1/namespaces/" + pathEscape(namespace) + "/pods/" + pathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return k8sPodInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return k8sPodInfo{}, fmt.Errorf("get pod: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return k8sPodInfo{}, fmt.Errorf("pod not found")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return k8sPodInfo{}, fmt.Errorf("get pod status %d", resp.StatusCode)
	}
	var out struct {
		Metadata struct {
			UID    string            `json:"uid"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
			NodeName           string `json:"nodeName"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return k8sPodInfo{}, fmt.Errorf("pod decode: %w", err)
	}
	return k8sPodInfo{
		UID:                out.Metadata.UID,
		Labels:             out.Metadata.Labels,
		ServiceAccountName: out.Spec.ServiceAccountName,
		NodeName:           out.Spec.NodeName,
	}, nil
}

func pathEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%", "%25"), "/", "%2F")
}

func serviceAccountFromUsername(username string) (namespace, serviceAccount string, ok bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(username, prefix)
	parts := strings.Split(rest, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// k8sResolveProfile derives the pod's clawpatrol profile from the match
// rule keyed on namespace + service_account: it reads the pod label named
// by that rule's profile_label (the plugin defaults it to
// K8sDefaultProfileLabel at build time) and requires the value to be in
// the rule's profiles allowlist. The profile is always server-derived
// from the live Pod object; clients never submit it.
func k8sResolveProfile(enr *config.CompiledK8sEnrollment, namespace, serviceAccount string, labels map[string]string) (string, error) {
	matched := false
	for _, rule := range enr.Matches {
		if rule.Namespace != namespace || rule.ServiceAccount != serviceAccount {
			continue
		}
		matched = true
		label := rule.ProfileLabel
		if label == "" {
			label = config.K8sDefaultProfileLabel
		}
		profile := strings.TrimSpace(labels[label])
		if profile == "" {
			return "", fmt.Errorf("pod is missing profile label %q", label)
		}
		if slices.Contains(rule.Profiles, profile) {
			return profile, nil
		}
	}
	if matched {
		return "", fmt.Errorf("pod profile is not in the match allowlist")
	}
	return "", fmt.Errorf("namespace/serviceaccount is not allowed")
}

// parseAllPeerStats parses a wireguard-go IpcGet (UAPI) dump into per-peer
// receive + handshake stats, keyed by hex public key.
func parseAllPeerStats(uapi string) map[string]wgDevPeerStat {
	out := map[string]wgDevPeerStat{}
	var cur string
	var st wgDevPeerStat
	var secs, nsec int64
	flush := func() {
		if cur != "" {
			if secs != 0 || nsec != 0 {
				st.lastHandshake = time.Unix(secs, nsec)
			}
			out[cur] = st
		}
		st = wgDevPeerStat{}
		secs, nsec = 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(uapi))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			cur = v
		case "rx_bytes":
			st.rxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "last_handshake_time_sec":
			secs, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	flush()
	return out
}
