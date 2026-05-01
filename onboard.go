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
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type onboardSession struct {
	deviceCode  string
	userCode    string // human-friendly, e.g. ABCD-1234
	created     time.Time
	approved    bool
	authKey     string // populated once approved
	loginServer string // empty for Tailscale Inc; Headscale URL for self-hosted
	err         string
	owner       string // who approved (for audit log)
}

type onboardRegistry struct {
	mu       sync.Mutex
	byDevice map[string]*onboardSession
	byUser   map[string]*onboardSession
	// ownerByIP maps a tailnet IP to the human approver email. Tailscale
	// OAuth client_credentials always mints `tag:client` keys, so whois
	// for onboarded devices returns "tagged-devices" — useless for
	// per-user OAuth integration scoping. After `clawall join` finishes,
	// the CLI hits /api/onboard/claim from the new tailnet IP; we record
	// (peer-ip → approver) here and use it as a whois override. Persisted
	// to disk so gateway restarts don't drop the mapping.
	ownerByIP map[string]string
	storePath string
}

func newOnboardRegistry() *onboardRegistry {
	return &onboardRegistry{
		byDevice:  map[string]*onboardSession{},
		byUser:    map[string]*onboardSession{},
		ownerByIP: map[string]string{},
	}
}

// Load attaches a disk file for owner-by-ip persistence and replays
// any existing entries. Call once after construction.
func (r *onboardRegistry) Load(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.storePath = filepath.Join(dir, "onboarded.json")
	b, err := os.ReadFile(r.storePath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &r.ownerByIP)
}

func (r *onboardRegistry) saveLocked() {
	if r.storePath == "" {
		return
	}
	b, _ := json.MarshalIndent(r.ownerByIP, "", "  ")
	_ = os.WriteFile(r.storePath, b, 0o600)
}

func (r *onboardRegistry) ClaimIP(deviceCode, ip string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.byDevice[deviceCode]
	if s == nil || s.owner == "" {
		return "", false
	}
	r.ownerByIP[ip] = s.owner
	r.saveLocked()
	return s.owner, true
}

func (r *onboardRegistry) OwnerForIP(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ownerByIP[ip]
}

func (r *onboardRegistry) ForgetIP(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ownerByIP, ip)
	r.saveLocked()
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
	mathrand.Seed(time.Now().UnixNano() + int64(timeNanoTail()))
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

func timeNanoTail() int64 { return time.Now().UnixNano() & 0xFFFF }

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

func newOnboarder(ts Tailscale) Onboarder {
	switch strings.ToLower(ts.Control) {
	case "wireguard":
		return &wireguardOnboarder{ts: ts}
	default:
		return &tailscaleOnboarder{ts: ts}
	}
}

type tailscaleOnboarder struct{ ts Tailscale }

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
