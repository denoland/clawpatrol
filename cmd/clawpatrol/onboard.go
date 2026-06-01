package main

// Device-flow onboarding for new clients that don't yet have Tailscale.
//
// Flow:
//   1. CLI: POST /api/onboard/start  → {device_code, user_code, verify_url, interval}
//   2. CLI prints user_code + opens verify_url in browser.
//   3. Admin (any user already on the tailnet who hits the dashboard)
//      visits /#/onboard/{user_code}, clicks "approve".
//   4. Server mints a single-use Tailscale auth key (Tailscale OAuth
//      client_credentials → POST /api/v2/tailnet/-/keys).
//   5. CLI: POST /api/onboard/poll?device_code=... → {auth_key} once
//      approved; CLI runs `tailscale up --authkey=<key>`.
//
// Codes expire in 10 minutes; auth keys minted are single-use,
// non-reusable, ephemeral=false.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// randomString returns a URL-safe base64 string of n random bytes.
// Used for onboard device codes, OAuth state/verifier, HITL IDs.
func randomString(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type onboardSession struct {
	deviceCode  string
	userCode    string // human-friendly, e.g. ABCD-1234
	created     time.Time
	approved    bool
	authKey     string // populated once approved
	loginServer string // "wireguard://<iface>" for WG mode; empty for Tailscale
	err         string
	owner       string // who approved (for audit log)
	profile     string // profile assigned at approval time
	hostname    string // client-supplied (os.Hostname) at /api/onboard/start
	apiToken    string // per-peer bearer for gated client API calls (env-pushdown)
	// wholeMachine: client asked at /start to install a persistent tailnet
	// node (system tailscale on linux, NE-routed on macOS) rather than
	// per-process tsnet. Determines whether the minted auth key is
	// ephemeral (per-process) or not (whole-machine).
	wholeMachine bool
}

// onboardRegistry persists onboarded peers in the `devices` table,
// keyed by tunnel IP (WG /32 or tsnet 100.x.x.x). The in-memory maps
// cache hot lookups (OwnerForIP / HostnameForIP / ProfileForIP fire
// on every request); mutations write through to SQLite.
//
// One transient case has no devices row: the tsnet "tsnet-<host>"
// placeholder used between approve time and the first
// /api/peer/tsnet/register call from the daemon. Such IDs are
// detected by prefix and skipped in upsertLocked so they don't
// surface as ghost dashboard rows.
type onboardRegistry struct {
	mu               sync.Mutex
	byDevice         map[string]*onboardSession
	byUser           map[string]*onboardSession
	ownerByIP        map[string]string
	hostnameByIP     map[string]string
	profileByIP      map[string]string
	extV4ByIP        map[string]string
	extV6ByIP        map[string]string
	canonicalByAlias map[string]string // alias IP → canonical device IP (e.g. fd7a:115c:a1e0::… → 100.x.x.x)
	knownDeviceIPs   map[string]bool   // all IPs present in devices table
	// resolveTriedAt caches the last time we asked tsnet WhoIs whether an
	// unknown peer IP corresponds to a known device. Without it, traffic
	// from any IP that genuinely has no devices-table mapping would
	// trigger a WhoIs lookup per packet.
	resolveTriedAt map[string]time.Time
	db             *sql.DB
}

func newOnboardRegistry() *onboardRegistry {
	return &onboardRegistry{
		byDevice:         map[string]*onboardSession{},
		byUser:           map[string]*onboardSession{},
		ownerByIP:        map[string]string{},
		hostnameByIP:     map[string]string{},
		profileByIP:      map[string]string{},
		extV4ByIP:        map[string]string{},
		extV6ByIP:        map[string]string{},
		canonicalByAlias: map[string]string{},
		knownDeviceIPs:   map[string]bool{},
		resolveTriedAt:   map[string]time.Time{},
	}
}

// tsnetPlaceholderPrefix marks an onboard session that's still
// awaiting the daemon's /api/peer/tsnet/register first call. The
// post-approve flow binds the api-token + chosen profile to
// "tsnet-<hostname>" until the daemon comes up and tells us the
// real tailnet IP. IDs starting with this prefix are scrubbed by
// upsertLocked so they don't surface as ghost devices rows.
const tsnetPlaceholderPrefix = "tsnet-"

// SetExternalIPs records the underlay endpoint addresses (v4 and/or v6)
// observed for the wg peer at ip. Mirrors unclaw's approvedIpv4 /
// approvedIpv6 model — the dashboard shows these in place of the wg /32,
// which is just a routing artefact. Persists through to the devices row.
func (r *onboardRegistry) SetExternalIPs(ip, v4, v6 string) {
	// Both v4 and v6 wg-side allowed_ips reach this path (one fd77::<n>
	// per peer); collapse to the canonical v4 so each device exists as a
	// single row. Without this the dashboard shows ghost fd77:: entries
	// alongside the real device.
	ip = canonicalPeerIP(ip)
	if ip == "" || (v4 == "" && v6 == "") {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	if v4 != "" && r.extV4ByIP[ip] != v4 {
		r.extV4ByIP[ip] = v4
		changed = true
	}
	if v6 != "" && r.extV6ByIP[ip] != v6 {
		r.extV6ByIP[ip] = v6
		changed = true
	}
	if changed {
		r.upsertLocked(ip)
	}
}

func (r *onboardRegistry) ExternalIPs(ip string) (v4, v6 string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.extV4ByIP[ip], r.extV6ByIP[ip]
}

func (r *onboardRegistry) ProfileForIP(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.profileByIP[ip]
}

// RegisterIPAlias maps alias to the same profile as canonical without
// creating a devices row. Used at startup so Tailscale IPv6 peer
// addresses (fd7a:) resolve to the same profile as the device's
// Tailscale IPv4 (100.x.x.x).
func (r *onboardRegistry) RegisterIPAlias(alias, canonical string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.profileByIP[canonical]; p != "" {
		r.profileByIP[alias] = p
	}
	r.canonicalByAlias[alias] = canonical
}

// AssignProfile records that a peer IP belongs to a named profile.
// Persists to the devices row.
func (r *onboardRegistry) AssignProfile(ip, profile string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profileByIP[ip] = profile
	r.upsertLocked(ip)
}

// assignProfileMemOnly records the profile mapping in memory without
// upserting a devices row. Used for the tsnet "tsnet-<hostname>"
// placeholder between approve time and the first daemon register
// call. upsertLocked refuses to persist IDs with the placeholder
// prefix so this is safe.
func (r *onboardRegistry) assignProfileMemOnly(ip, profile string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profileByIP[ip] = profile
}

// AgentIPFor returns the device IP that traffic from ip should be
// attributed to. Today the only remapping is the IPv6 ULA alias
// (fd7a:115c:a1e0::… → 100.x.x.x) used by Tailscale-mode peers; for
// every other peer ip is returned unchanged.
func (r *onboardRegistry) AgentIPFor(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if canonical := r.canonicalByAlias[ip]; canonical != "" {
		return canonical
	}
	return ip
}

// Load attaches the SQLite-backed `devices` table and replays every
// row into the in-memory caches. Call once after construction.
func (r *onboardRegistry) Load(db *sql.DB) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.db = db
	if db == nil {
		return nil
	}
	rows, err := db.Query("SELECT id, name, profile, external_ipv4, external_ipv6 FROM devices")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			ip      string
			name    sql.NullString
			profile sql.NullString
			v4      sql.NullString
			v6      sql.NullString
		)
		if err := rows.Scan(&ip, &name, &profile, &v4, &v6); err != nil {
			return err
		}
		r.knownDeviceIPs[ip] = true
		if name.Valid {
			r.hostnameByIP[ip] = name.String
		}
		if profile.Valid {
			r.profileByIP[ip] = profile.String
		}
		if v4.Valid {
			r.extV4ByIP[ip] = v4.String
		}
		if v6.Valid {
			r.extV6ByIP[ip] = v6.String
		}
	}
	return rows.Err()
}

// HasDevice reports whether ip has a row in the devices table.
// Used to filter out sessions from ephemeral peers that no longer exist.
func (r *onboardRegistry) HasDevice(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.knownDeviceIPs[ip]
}

// upsertLocked writes the in-memory tuple for ip into the devices row.
// Caller holds r.mu. Persists the row for any IP we've seen claim or
// hostname/profile data; rows for un-claimed IPs land with NULLs and
// fill in as the claim flow progresses.
func (r *onboardRegistry) upsertLocked(ip string) {
	if r.db == nil {
		return
	}
	// Placeholder IDs (e.g. "tsnet-<hostname>" between approve and the
	// daemon's first register call) never get a devices row — they
	// only exist in profileByIP to remember the operator-picked
	// profile across the gap.
	if strings.HasPrefix(ip, tsnetPlaceholderPrefix) {
		return
	}
	if _, seen := r.profileByIP[ip]; !seen {
		if _, hn := r.hostnameByIP[ip]; !hn {
			if _, owner := r.ownerByIP[ip]; !owner {
				if _, v4 := r.extV4ByIP[ip]; !v4 {
					if _, v6 := r.extV6ByIP[ip]; !v6 {
						return
					}
				}
			}
		}
	}
	now := time.Now().UnixNano()
	_, _ = r.db.Exec(`
		INSERT INTO devices (id, name, profile, external_ipv4, external_ipv6, created_ns, last_seen_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name          = excluded.name,
			profile       = excluded.profile,
			external_ipv4 = excluded.external_ipv4,
			external_ipv6 = excluded.external_ipv6,
			last_seen_ns  = excluded.last_seen_ns
	`, ip, nullStr(r.hostnameByIP[ip]), nullStr(r.profileByIP[ip]),
		nullStr(r.extV4ByIP[ip]), nullStr(r.extV6ByIP[ip]),
		now, now)
	r.knownDeviceIPs[ip] = true
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ClaimIP binds a peer IP to its approver. hostnameOverride wins over
// the value captured at /api/onboard/start — older CLIs didn't send a
// hostname at start, so the post-tunnel claim is the reliable hook.
func (r *onboardRegistry) ClaimIP(deviceCode, ip, hostnameOverride string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.byDevice[deviceCode]
	if s == nil || s.owner == "" {
		return "", false
	}
	r.ownerByIP[ip] = s.owner
	if hostnameOverride != "" {
		r.hostnameByIP[ip] = hostnameOverride
	} else if s.hostname != "" {
		r.hostnameByIP[ip] = s.hostname
	}
	r.upsertLocked(ip)
	return s.owner, true
}

// SetHostname records a hostname for a peer IP outside the onboard
// device-code flow (e.g. `clawpatrol run` register, which already
// authenticated via api-token).
func (r *onboardRegistry) SetHostname(ip, hostname string) {
	if ip == "" || hostname == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostnameByIP[ip] = hostname
	r.upsertLocked(ip)
}

func (r *onboardRegistry) OwnerForIP(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ownerByIP[ip]
}

func (r *onboardRegistry) HostnameForIP(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hostnameByIP[ip]
}

// IPForHostname returns the wg IP previously bound to (owner, hostname),
// if any. Lets the approve flow recycle the existing /32 when the same
// machine re-runs `clawpatrol join` — without it, every rejoin minted
// a fresh IP and the dashboard accumulated duplicate device rows.
func (r *onboardRegistry) IPForHostname(owner, hostname string) string {
	if hostname == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, hn := range r.hostnameByIP {
		if hn != hostname {
			continue
		}
		if owner != "" {
			if o, ok := r.ownerByIP[ip]; ok && o != "" && o != owner {
				continue
			}
		}
		return ip
	}
	return ""
}

// UniqueIPForHostname returns a device IP iff exactly one devices row has
// this hostname. Used to coalesce a tailnet peer that has rejoined under
// a fresh tailnet IP back onto its existing device row. Returns "" on
// collisions so we never silently merge two distinct hosts that happen
// to share a hostname (e.g. ephemeral clawpatrol-run nodes that all
// register as "clawpatrol-run").
func (r *onboardRegistry) UniqueIPForHostname(hostname string) string {
	if hostname == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	found := ""
	for ip, hn := range r.hostnameByIP {
		if hn != hostname {
			continue
		}
		if !r.knownDeviceIPs[ip] {
			continue
		}
		if found != "" && found != ip {
			return ""
		}
		found = ip
	}
	return found
}

// ClaimAliasResolve returns true if we should run a WhoIs lookup for ip
// to try to map it onto a known device, and false if a recent attempt
// already settled the question (positive or negative). The first caller
// in a `within` window wins; subsequent callers skip the lookup so a
// peer with no matching device doesn't trigger one WhoIs round-trip per
// packet. Stamping the time inside the same critical section makes the
// check-and-claim atomic across concurrent callers.
func (r *onboardRegistry) ClaimAliasResolve(ip string, within time.Duration) bool {
	if ip == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.knownDeviceIPs[ip] {
		return false
	}
	if _, ok := r.canonicalByAlias[ip]; ok {
		return false
	}
	if t, ok := r.resolveTriedAt[ip]; ok && time.Since(t) < within {
		return false
	}
	r.resolveTriedAt[ip] = time.Now()
	return true
}

func (r *onboardRegistry) ForgetIP(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ownerByIP, ip)
	delete(r.hostnameByIP, ip)
	delete(r.profileByIP, ip)
	delete(r.extV4ByIP, ip)
	delete(r.extV6ByIP, ip)
	if r.db != nil {
		_, _ = r.db.Exec("DELETE FROM devices WHERE id = ?", ip)
	}
}

func (r *onboardRegistry) start() *onboardSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	s := &onboardSession{
		deviceCode: randomString(48),
		userCode:   randomUserCode(),
		created:    time.Now(),
	}
	r.byDevice[s.deviceCode] = s
	r.byUser[s.userCode] = s
	return s
}

func (r *onboardRegistry) byUserCode(code string) *onboardSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	return r.byUser[strings.ToUpper(strings.TrimSpace(code))]
}

func (r *onboardRegistry) byDeviceCode(code string) *onboardSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	return r.byDevice[code]
}

func (r *onboardRegistry) gcLocked() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, s := range r.byDevice {
		if s.created.Before(cutoff) {
			delete(r.byDevice, k)
			delete(r.byUser, s.userCode)
		}
	}
}

// randomUserCode returns a friendly 8-char code "ABCD-1234".
func randomUserCode() string {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I/O for legibility
	const digits = "23456789"
	var b [4]byte
	rand.Read(b[:])
	out := make([]byte, 0, 9)
	for i := 0; i < 4; i++ {
		out = append(out, letters[int(b[i])%len(letters)])
	}
	out = append(out, '-')
	rand.Read(b[:])
	for i := 0; i < 4; i++ {
		out = append(out, digits[int(b[i])%len(digits)])
	}
	return string(out)
}

// Onboarder mints a single-use auth artefact + tells the client which
// control-plane to register against. Implementations:
//   - tailscaleOnboarder — Tailscale Inc OAuth
//   - wireguardOnboarder — plain self-hosted WireGuard, no SaaS
type Onboarder interface {
	// MintKey provisions a fresh client. authKey is the secret material
	// handed to the device (Tailscale auth-key, or a wg-quick conf for
	// the WG path). loginServer prefixes the CLI branch select
	// ("wireguard://…" or empty for Tailscale Inc). peerIP, when
	// non-empty, is the IP the server allocated for this peer — the
	// caller registers it in the onboard registry so per-user OAuth
	// lookup works without a separate claim round-trip from the CLI.
	MintKey(ctx context.Context, reuseIP string, wholeMachine bool) (authKey, loginServer, peerIP string, err error)
}

// newOnboarder picks the transport branch the gateway should use to
// mint a peer identity for a joining device. When both transports
// are enabled, WireGuard wins — its onboarding flow yields a
// wg-quick conf the device can apply without needing a Tailscale
// account, which is the more permissive path. Operators who want
// every device to land on Tailscale should disable the `wireguard
// {}` block.
func newOnboarder(ts JoinConfig) Onboarder {
	if ts.WGEnabled {
		return &wireguardOnboarder{ts: ts}
	}
	return &tailscaleOnboarder{ts: ts}
}

type tailscaleOnboarder struct{ ts JoinConfig }

func (t *tailscaleOnboarder) MintKey(ctx context.Context, _ string, _ bool) (string, string, string, error) {
	// One persistent (non-ephemeral) auth key per device. The Linux
	// daemon (cmd/clawpatrol daemon_linux.go) holds one stable tsnet identity
	// shared across every `clawpatrol run` on the host, so the
	// per-process ephemeral model is gone. Whole-machine joins on
	// Linux also want a persistent node so the host survives reboots.
	k, err := mintTailscaleAuthKey(ctx, t.ts, false)
	return k, "", "", err
}

// mintTailscaleAuthKey calls Tailscale's OAuth + auth-key API to mint
// a single-use auth key. ephemeral=true makes the registered node
// auto-disappear on disconnect (used by per-process tsnet runs);
// ephemeral=false keeps the node registered across reconnects (used
// by whole-machine joins and the per-host daemon).
//
// The key is non-reusable: it authenticates exactly one node
// registration, then becomes inert. Daemon respawns and reboots reuse
// the persisted tsnet state dir (no key needed — tsnet ignores the
// AuthKey field once the local state is past NeedsLogin). Limits the
// blast radius if the on-disk auth-key file leaks: an attacker can
// register at most one extra tailnet node before the key is burned.
func mintTailscaleAuthKey(ctx context.Context, ts JoinConfig, ephemeral bool) (string, error) {
	clientID := resolveTemplate(ts.OAuthClientID)
	clientSecret := resolveTemplate(ts.OAuthClientSecret)
	if clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("tailscale oauth not configured (set tailscale.oauth_client_id/oauth_client_secret)")
	}
	// 1. exchange client_credentials for short-lived bearer token.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	tokReq, _ := http.NewRequestWithContext(ctx, "POST",
		"https://api.tailscale.com/api/v2/oauth/token",
		strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		return "", fmt.Errorf("tailscale oauth: %w", err)
	}
	defer func() { _ = tokResp.Body.Close() }()
	if tokResp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(tokResp.Body, 1024))
		return "", fmt.Errorf("tailscale oauth %d: %s", tokResp.StatusCode, string(body))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokResp.Body, 64<<10)).Decode(&tok); err != nil {
		return "", fmt.Errorf("tailscale oauth: decode: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("tailscale oauth: empty access_token")
	}

	// 2. mint auth key.
	//
	// SECURITY: every minted auth key MUST carry at least one tag.
	// An untagged auth key produces an "owner-associated" tailnet
	// node — whois on requests from that node returns the OAuth
	// client owner's user login, which would then match a
	// dashboard_operators allowlist entry (e.g. "*@example.com") and
	// silently bypass the dashboard auth gate. The fallback to
	// `tag:client` below is load-bearing — do not let an empty
	// tags slice reach Tailscale's create-key API under any
	// configuration. If you add a new code path here, re-check
	// this invariant.
	tags := ts.TailscaleTags
	if len(tags) == 0 {
		tags = []string{"tag:client"}
	}
	if len(tags) == 0 {
		// Belt-and-suspenders: refuse to call the API with an
		// empty tag list even if the default above is ever
		// changed in a way that lets the slice stay empty.
		return "", fmt.Errorf("tailscale auth-key mint: refusing to mint untagged key")
	}
	keyReqBody, _ := json.Marshal(map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     ephemeral,
					"preauthorized": true,
					"tags":          tags,
				},
			},
		},
		"expirySeconds": 90 * 24 * 3600,
	})
	keyReq, _ := http.NewRequestWithContext(ctx, "POST",
		"https://api.tailscale.com/api/v2/tailnet/-/keys",
		strings.NewReader(string(keyReqBody)))
	keyReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	keyReq.Header.Set("Content-Type", "application/json")
	keyResp, err := http.DefaultClient.Do(keyReq)
	if err != nil {
		return "", fmt.Errorf("tailscale key: post: %w", err)
	}
	defer func() { _ = keyResp.Body.Close() }()
	if keyResp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(keyResp.Body, 1024))
		return "", fmt.Errorf("tailscale key %d: %s", keyResp.StatusCode, string(body))
	}
	var key struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(keyResp.Body, 64<<10)).Decode(&key); err != nil {
		return "", fmt.Errorf("tailscale key: decode: %w", err)
	}
	if key.Key == "" {
		return "", fmt.Errorf("tailscale key: empty key in response")
	}
	return key.Key, nil
}
func (w *webMux) apiOnboardStart(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	s := w.onboard.start()
	// CLI passes its os.Hostname() so the dashboard shows a real
	// device name instead of just the WG-side IP. Optional — we still
	// fall back gracefully when missing.
	hn := strings.TrimSpace(r.URL.Query().Get("hostname"))
	// `clawpatrol join --profile X` forwards X here so the approver
	// doesn't have to pick it manually. Stored as the session-level
	// suggestion; the dashboard's approve call can still override.
	prof := strings.TrimSpace(r.URL.Query().Get("profile"))
	// `clawpatrol join --whole-machine` → persistent tailnet node
	// (auth key minted with ephemeral=false). Default = per-process
	// tsnet (ephemeral=true), matching macOS NE behavior.
	wm := r.URL.Query().Get("whole_machine") == "1"
	if hn != "" || prof != "" || wm {
		w.onboard.mu.Lock()
		if hn != "" {
			s.hostname = hn
		}
		if prof != "" {
			s.profile = prof
		}
		s.wholeMachine = wm
		w.onboard.mu.Unlock()
	}
	// Build the verify URL that points at the dashboard approval page.
	// In tsnet mode the approving operator is on the tailnet — use the
	// tailnet-direct HTTP URL (http://<100.x.x.x>:<info_port>) so they
	// don't have to go through the Funnel HTTPS relay. Use IP directly
	// to avoid MagicDNS resolution issues with OS-hostname vs registered name.
	verifyURL := w.publicURL
	if w.g != nil && w.g.cfg != nil && w.g.cfg.PublicURL() != "" {
		verifyURL = w.g.cfg.PublicURL()
	}
	if w.g != nil && w.g.tailscaleIP != "" && w.g.cfg.DashboardListen() != "" {
		port := w.g.cfg.DashboardListen()
		if i := strings.LastIndexByte(port, ':'); i >= 0 {
			port = port[i+1:]
		}
		if port != "" {
			verifyURL = fmt.Sprintf("http://%s:%s", w.g.tailscaleIP, port)
		}
	}
	if verifyURL == "" {
		scheme := "http"
		if strings.HasSuffix(r.Host, ".ts.net") || r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		verifyURL = scheme + "://" + r.Host
	}
	verifyURL = strings.TrimRight(verifyURL, "/") + "/#/onboard/" + s.userCode
	writeJSON(rw, map[string]any{
		"device_code": s.deviceCode,
		"user_code":   s.userCode,
		"verify_url":  verifyURL,
		"interval":    3,
		"expires_in":  600,
	})
}

// apiOnboardLookup returns user_code session info for the dashboard
// approval page. No secrets exposed (just code + age). Includes the
// gateway's CA SHA-256 fingerprint so the approving operator can
// compare it against what the CLI prints on the new device — out-
// of-band confirmation that no on-path attacker substituted the CA
// the CLI just fetched over plain HTTP.
func (w *webMux) apiOnboardLookup(rw http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	s := w.onboard.byUserCode(code)
	if s == nil {
		http.Error(rw, "unknown or expired code", 404)
		return
	}
	writeJSON(rw, map[string]any{
		"user_code":      s.userCode,
		"approved":       s.approved,
		"created_at":     s.created.Unix(),
		"ca_fingerprint": w.caFingerprint(),
	})
}

// apiOnboardApprove is hit by the dashboard "approve" button.
// Approval is an operator action: dashboardAuthGate must authenticate
// the request (root password or tailnet allowlist) before this handler
// can approve a pending device.
func (w *webMux) apiOnboardApprove(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := principalFromContext(r.Context()); !ok {
		http.Error(rw, "approval requires an authenticated operator", http.StatusForbidden)
		return
	}
	owner, _ := w.selectedProfileForRequest(r)
	if owner == "" {
		http.Error(rw, "approval requires a profile", http.StatusForbidden)
		return
	}
	code := r.URL.Query().Get("code")
	s := w.onboard.byUserCode(code)
	if s == nil {
		http.Error(rw, "unknown or expired code", 404)
		return
	}
	// Operator picks which profile this device joins. Priority:
	// dashboard query param → CLI suggestion stashed at /start time →
	// profile named "default" → first profile in source order.
	profile := r.URL.Query().Get("profile")
	if profile == "" {
		profile = s.profile
	}
	if profile == "" {
		profile = defaultProfileName(w.g.cfg.Policy)
	}
	w.onboard.mu.Lock()
	if s.approved {
		w.onboard.mu.Unlock()
		writeJSON(rw, map[string]any{"already": true})
		return
	}
	s.approved = true
	s.owner = owner
	s.profile = profile
	hostname := s.hostname
	w.onboard.mu.Unlock()

	// Recycle the wg /32 already bound to (owner, hostname) so a rejoin
	// from the same machine doesn't spawn a duplicate device row.
	reuseIP := w.onboard.IPForHostname(owner, hostname)

	// Mint key in background so the approve click returns fast.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		key, loginServer, peerIP, err := newOnboarder(w.ts).MintKey(ctx, reuseIP, s.wholeMachine)
		w.onboard.mu.Lock()
		if err != nil {
			s.err = err.Error()
			w.onboard.mu.Unlock()
			return
		}
		s.authKey = key
		s.loginServer = loginServer
		dc := s.deviceCode
		w.onboard.mu.Unlock()
		// WG path: server allocated peerIP and knows the approver, so
		// register the (ip → owner) mapping right here. Saves the CLI
		// from making a /api/onboard/claim round-trip after wg-quick
		// (which is racy: the default route is now the tunnel and the
		// public gateway URL becomes unreachable).
		if peerIP != "" {
			w.onboard.ClaimIP(dc, peerIP, "")
			if profile != "" {
				w.onboard.AssignProfile(peerIP, profile)
			}
			// Seed the agents registry so the dashboard shows the
			// device immediately, before it sends any traffic.
			if w.g.agents != nil {
				w.g.agents.Seed(peerIP)
			}
			// Mint the per-peer bearer the client uses for gated
			// API calls (currently /api/env-pushdown). Stored hashed
			// in `peer_api_tokens`; raw token is returned exactly
			// once via /api/onboard/poll.
			if token, perr := mintAndPersistPeerAPIToken(w.g.db, peerIP); perr == nil {
				w.onboard.mu.Lock()
				s.apiToken = token
				w.onboard.mu.Unlock()
			} else {
				log.Printf("api-token mint for %s: %v", peerIP, perr)
			}
		} else if loginServer == "" && !s.wholeMachine {
			// Tsnet daemon mode: no devices row yet — the tailnet IP
			// only exists once the per-host daemon joins, which happens
			// later when the operator runs `clawpatrol run`. Hold the
			// profile in memory only against a synthetic placeholder
			// and bind the api-token to it; both get repointed by
			// /api/peer/tsnet/register on the daemon's first boot.
			s2 := w.onboard.byDeviceCode(dc)
			parentID := tsnetPlaceholderPrefix + dc
			if s2 != nil && s2.hostname != "" {
				parentID = tsnetPlaceholderPrefix + s2.hostname
			}
			if profile != "" {
				w.onboard.assignProfileMemOnly(parentID, profile)
			}
			if token, perr := mintAndPersistPeerAPIToken(w.g.db, parentID); perr == nil {
				w.onboard.mu.Lock()
				s.apiToken = token
				w.onboard.mu.Unlock()
			} else {
				log.Printf("api-token mint for %s: %v", parentID, perr)
			}
		}
	}()
	writeJSON(rw, map[string]any{"approved": true})
}

// apiOnboardClaim is hit by the CLI right after `tailscale up`
// finishes. The peer IP (the new device's tailnet IP) gets associated
// with the approver email. Subsequent agent traffic from that IP
// resolves to the approver in lieu of the useless "tagged-devices"
// whois result.
func (w *webMux) apiOnboardClaim(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	dc := r.URL.Query().Get("device_code")
	if dc == "" {
		http.Error(rw, "missing device_code", 400)
		return
	}
	// CLI passes its own tailnet IP via ?ip=. We can't trust
	// r.RemoteAddr because tailscale funnel proxies through localhost
	// and the device_code already binds this to a specific approval —
	// you can't claim someone else's IP without their device_code.
	host := r.URL.Query().Get("ip")
	if host == "" {
		host = r.RemoteAddr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
	}
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))
	owner, ok := w.onboard.ClaimIP(dc, host, hostname)
	if !ok {
		log.Printf("onboard claim: unknown/unapproved device_code=%s ip=%s", truncate(dc, 16), host)
		http.Error(rw, "unknown or unapproved device_code", 404)
		return
	}
	log.Printf("onboard claim: %s → %s (hostname=%q)", host, owner, hostname)
	// Mirror profile mapping onto the peer's IPv6 ULA — whole-machine
	// tsnet traffic frequently arrives on fd7a:115c:a1e0::/48 not the
	// 100.x IPv4 that claim() registered.
	w.g.seedTsnetIPv6Alias(host)
	resp := map[string]string{"owner": owner, "ip": host}
	// Mint the per-peer bearer the client uses for gated API calls
	// (env-pushdown, ephemeral tsnet key). In Tailscale mode the peer IP
	// isn't known at approve time, so we mint it here instead.
	if token, err := mintAndPersistPeerAPIToken(w.g.db, host); err == nil {
		resp["api_token"] = token
	}
	writeJSON(rw, resp)
}

// apiPeerTsnetRegister is the daemon's one-shot self-registration on
// first boot after `clawpatrol join`: the api-token minted at approve
// time is bound to a synthetic "tsnet-<host>" placeholder; the daemon
// now has its real tailnet IP and asks the gateway to rebind the
// token + create the real devices row. Subsequent calls (later daemon
// boots, gateway restarts) reach the no-op branch — the token's
// peer_ip is already the real IP, nothing to do.
//
// Auth: bearer api-token in the Authorization header. The path is
// /api/peer/tsnet/register — no "ephemeral" in the name because the
// daemon model has one persistent peer per host, not a pool of
// short-lived ones.
func (w *webMux) apiPeerTsnetRegister(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	parentIP := peerIPForAPIToken(w.g.db, token)
	if parentIP == "" {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	tsnetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	if tsnetIP == "" {
		http.Error(rw, "missing ip", http.StatusBadRequest)
		return
	}
	if ip, err := netip.ParseAddr(tsnetIP); err != nil || !ip.IsValid() {
		http.Error(rw, "invalid ip", http.StatusBadRequest)
		return
	}
	if w.g.onboard == nil {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))
	if strings.HasPrefix(parentIP, tsnetPlaceholderPrefix) {
		// First call — promote the synthetic placeholder to a real
		// devices row keyed on the tailnet IP. Rebind the api-token,
		// drop the placeholder from in-memory state, copy across the
		// profile picked at approve time.
		profile := w.g.onboard.ProfileForIP(parentIP)
		_, _ = w.g.db.Exec("UPDATE peer_api_tokens SET peer_ip=? WHERE peer_ip=?", tsnetIP, parentIP)
		w.g.onboard.ForgetIP(parentIP)
		if w.g.agents != nil {
			w.g.agents.Delete(parentIP)
		}
		if profile != "" {
			w.g.onboard.AssignProfile(tsnetIP, profile)
		}
		if hostname != "" {
			w.g.onboard.SetHostname(tsnetIP, hostname)
		}
		if w.g.agents != nil {
			w.g.agents.Seed(tsnetIP)
		}
	}
	// Map the daemon's IPv6 ULA too — tsnet traffic from this peer
	// frequently arrives on fd7a:115c:a1e0::/48 rather than the 100.x.
	w.g.seedTsnetIPv6Alias(tsnetIP)
	rw.WriteHeader(http.StatusNoContent)
}

// apiOnboardPoll is hit by the CLI to retrieve the auth key once
// approved. Uses standard device-flow status codes via JSON.
func (w *webMux) apiOnboardPoll(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	dc := r.URL.Query().Get("device_code")
	s := w.onboard.byDeviceCode(dc)
	if s == nil {
		writeJSON(rw, map[string]string{"error": "expired_token"})
		return
	}
	w.onboard.mu.Lock()
	defer w.onboard.mu.Unlock()
	if s.err != "" {
		writeJSON(rw, map[string]string{"error": "server_error", "detail": s.err})
		return
	}
	if !s.approved {
		writeJSON(rw, map[string]string{"error": "authorization_pending"})
		return
	}
	if s.authKey == "" {
		writeJSON(rw, map[string]string{"error": "slow_down"})
		return
	}
	resp := map[string]any{
		"auth_key":     s.authKey,
		"api_token":    s.apiToken,
		"approved_by":  s.owner,
		"login_server": s.loginServer, // empty = Tailscale Inc default
	}
	// In Tailscale mode include gateway_host, gateway_ip, and control_url
	// so the client can write mode marker files for `clawpatrol run`.
	// gateway_ip (100.x.x.x) lets the client write tailnet-url directly
	// without a fragile peer-name lookup.
	if s.loginServer == "" {
		gwHost := w.ts.Hostname
		if gwHost == "" {
			gwHost = "clawpatrol-gateway"
		}
		// Prefer the actual registered node name (may differ from the
		// configured hostname when tsnet resolved a conflict, e.g.
		// "clawpatrol-gateway-1" vs "clawpatrol-gateway").
		if w.g != nil && w.g.tailscaleHostname != "" {
			gwHost = w.g.tailscaleHostname
		}
		resp["gateway_host"] = gwHost
		resp["control_url"] = w.ts.ControlURL
		if w.g != nil && w.g.tailscaleIP != "" {
			resp["gateway_ip"] = w.g.tailscaleIP
		}
		// CA cert delivered over the approved Funnel/onboard channel —
		// the gateway's /ca.crt is intentionally not exposed publicly
		// in tsnet mode (CA fetched after approval, inside the
		// Let's-Encrypt-authenticated Funnel TLS).
		if w.g != nil && w.g.certs != nil {
			if pem := w.g.certs.CertPEM(); len(pem) > 0 {
				resp["ca_pem"] = string(pem)
			}
		}
	}
	writeJSON(rw, resp)
}
