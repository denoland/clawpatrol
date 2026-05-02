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
	db           *sql.DB
}

func newOnboardRegistry() *onboardRegistry {
	return &onboardRegistry{
		byDevice:     map[string]*onboardSession{},
		byUser:       map[string]*onboardSession{},
		ownerByIP:    map[string]string{},
		hostnameByIP: map[string]string{},
		profileByIP:  map[string]string{},
	}
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
	rows, err := db.Query("SELECT id, name, profile FROM devices")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			ip      string
			name    sql.NullString
			profile sql.NullString
		)
		if err := rows.Scan(&ip, &name, &profile); err != nil {
			return err
		}
		if name.Valid {
			r.hostnameByIP[ip] = name.String
		}
		if profile.Valid {
			r.profileByIP[ip] = profile.String
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
				return
			}
		}
	}
	now := time.Now().UnixNano()
	_, _ = r.db.Exec(`
		INSERT INTO devices (id, name, profile, created_ns, last_seen_ns)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name         = excluded.name,
			profile      = excluded.profile,
			last_seen_ns = excluded.last_seen_ns
	`, ip, nullStr(r.hostnameByIP[ip]), nullStr(r.profileByIP[ip]), now, now)
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

func (r *onboardRegistry) ForgetIP(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ownerByIP, ip)
	delete(r.hostnameByIP, ip)
	delete(r.profileByIP, ip)
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
	MintKey(ctx context.Context) (authKey, loginServer, peerIP string, err error)
}

func newOnboarder(ts GatewayConfig) Onboarder {
	switch strings.ToLower(ts.Control) {
	case "wireguard":
		return &wireguardOnboarder{ts: ts}
	default:
		return &tailscaleOnboarder{ts: ts}
	}
}

type tailscaleOnboarder struct{ ts GatewayConfig }

func (t *tailscaleOnboarder) MintKey(ctx context.Context) (string, string, string, error) {
	k, err := mintTailscaleAuthKey(ctx, t.ts)
	// Tailscale assigns peer IPs from the tailnet — we don't know the
	// new device's IP at mint time, so claim happens later via /api/
	// onboard/claim from the CLI once `tailscale up` succeeds.
	return k, "", "", err
}

// mintTailscaleAuthKey calls Tailscale's OAuth + auth-key API to create
// a single-use, non-ephemeral auth key the new client can use to join
// the tailnet exactly once.
func mintTailscaleAuthKey(ctx context.Context, ts GatewayConfig) (string, error) {
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
