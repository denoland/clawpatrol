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
}

// onboardRegistry persists onboarded peers in the `devices` table,
// keyed by WG tunnel IP. The in-memory maps cache hot lookups
// (OwnerForIP / HostnameForIP / ProfileForIP fire on every request);
// mutations write through to SQLite.
type onboardRegistry struct {
	mu           sync.Mutex
	byDevice     map[string]*onboardSession
	byUser       map[string]*onboardSession
	ownerByIP    map[string]string
	hostnameByIP map[string]string
	profileByIP  map[string]string
	extV4ByIP    map[string]string
	extV6ByIP    map[string]string
	db           *sql.DB
}

func newOnboardRegistry() *onboardRegistry {
	return &onboardRegistry{
		byDevice:     map[string]*onboardSession{},
		byUser:       map[string]*onboardSession{},
		ownerByIP:    map[string]string{},
		hostnameByIP: map[string]string{},
		profileByIP:  map[string]string{},
		extV4ByIP:    map[string]string{},
		extV6ByIP:    map[string]string{},
	}
}

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

// AssignProfile records that a peer IP belongs to a named profile.
// Persists to the devices row.
func (r *onboardRegistry) AssignProfile(ip, profile string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profileByIP[ip] = profile
	r.upsertLocked(ip)
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
	defer rows.Close()
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

// upsertLocked writes the in-memory tuple for ip into the devices row.
// Caller holds r.mu. Persists the row for any IP we've seen claim or
// hostname/profile data; rows for un-claimed IPs land with NULLs and
// fill in as the claim flow progresses.
func (r *onboardRegistry) upsertLocked(ip string) {
	if r.db == nil {
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
	MintKey(ctx context.Context, reuseIP string) (authKey, loginServer, peerIP string, err error)
}

func newOnboarder(ts Tailscale) Onboarder {
	switch strings.ToLower(ts.Control) {
	case "wireguard":
		return &wireguardOnboarder{ts: ts}
	default:
		return &tailscaleOnboarder{ts: ts}
	}
}

type tailscaleOnboarder struct{ ts Tailscale }

func (t *tailscaleOnboarder) MintKey(ctx context.Context, _ string) (string, string, string, error) {
	k, err := mintTailscaleAuthKey(ctx, t.ts)
	// Tailscale assigns peer IPs from the tailnet — we don't know the
	// new device's IP at mint time, so claim happens later via /api/
	// onboard/claim from the CLI once `tailscale up` succeeds.
	return k, "", "", err
}

// mintTailscaleAuthKey calls Tailscale's OAuth + auth-key API to create
// a single-use, non-ephemeral auth key the new client can use to join
// the tailnet exactly once.
func mintTailscaleAuthKey(ctx context.Context, ts Tailscale) (string, error) {
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
	defer tokResp.Body.Close()
	if tokResp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(tokResp.Body, 1024))
		return "", fmt.Errorf("tailscale oauth %d: %s", tokResp.StatusCode, string(body))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("tailscale oauth: empty access_token")
	}

	// 2. mint auth key.
	tags := ts.Tags
	if len(tags) == 0 {
		tags = []string{"tag:client"}
	}
	keyReqBody, _ := json.Marshal(map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     false,
					"preauthorized": true,
					"tags":          tags,
				},
			},
		},
		"expirySeconds": 600,
	})
	keyReq, _ := http.NewRequestWithContext(ctx, "POST",
		"https://api.tailscale.com/api/v2/tailnet/-/keys",
		strings.NewReader(string(keyReqBody)))
	keyReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	keyReq.Header.Set("Content-Type", "application/json")
	keyResp, err := http.DefaultClient.Do(keyReq)
	if err != nil {
		return "", err
	}
	defer keyResp.Body.Close()
	if keyResp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(keyResp.Body, 1024))
		return "", fmt.Errorf("tailscale key %d: %s", keyResp.StatusCode, string(body))
	}
	var key struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(keyResp.Body).Decode(&key); err != nil {
		return "", err
	}
	if key.Key == "" {
		return "", fmt.Errorf("tailscale key: empty key in response")
	}
	return key.Key, nil
}
func (w *webMux) apiOnboardStart(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
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
	if hn != "" || prof != "" {
		w.onboard.mu.Lock()
		if hn != "" {
			s.hostname = hn
		}
		if prof != "" {
			s.profile = prof
		}
		w.onboard.mu.Unlock()
	}
	// Prefer the operator-configured public_url so brand-new clients
	// see a real URL. Fall back to the request's Host header for
	// dev / direct-IP setups. Tailscale Funnel hostnames (*.ts.net)
	// are always HTTPS, so detect those explicitly.
	verifyURL := w.publicURL
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
// approval page. No secrets exposed (just code + age).
func (w *webMux) apiOnboardLookup(rw http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	s := w.onboard.byUserCode(code)
	if s == nil {
		http.Error(rw, "unknown or expired code", 404)
		return
	}
	writeJSON(rw, map[string]any{
		"user_code":  s.userCode,
		"approved":   s.approved,
		"created_at": s.created.Unix(),
	})
}

// apiOnboardApprove is hit by the dashboard "approve" button. The
// caller must be an existing tailnet member (whois succeeds) — this
// gates onboarding behind an existing trusted user.
func (w *webMux) apiOnboardApprove(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	owner, _ := w.ownerForCaller(r)
	if owner == "" {
		http.Error(rw, "approval requires an authenticated tailnet caller (or set admin_email in gateway.hcl)", 403)
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
		key, loginServer, peerIP, err := newOnboarder(w.ts).MintKey(ctx, reuseIP)
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
		http.Error(rw, "POST", 405)
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
	writeJSON(rw, map[string]string{"owner": owner, "ip": host})
}

// apiOnboardPoll is hit by the CLI to retrieve the auth key once
// approved. Uses standard device-flow status codes via JSON.
func (w *webMux) apiOnboardPoll(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
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
	writeJSON(rw, map[string]any{
		"auth_key":     s.authKey,
		"approved_by":  s.owner,
		"login_server": s.loginServer, // empty = Tailscale Inc default
	})
}

var displayOrder = []string{"claude", "codex", "github"}
