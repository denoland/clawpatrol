package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/runtime"
)

//go:embed all:www/dist
var dashboardFS embed.FS

//go:embed www/login.html
var loginHTML string

var loginTpl = template.Must(template.New("login").Parse(loginHTML))

type IntegrationRow struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Type     string              `json:"type"` // credential plugin type
	HasOAuth bool                `json:"has_oauth"`
	Slots    []config.SecretSlot `json:"slots,omitempty"`
	Owners   []Owner             `json:"owners"`
}

type Owner struct {
	Owner     string `json:"owner"`
	Connected bool   `json:"connected"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type oauthSession struct {
	verifier string
	state    string
	cfg      *oauth2.Config
	id       string
	owner    string
	created  time.Time
}

type webMux struct {
	g         *Gateway
	caDir     string
	ts        Tailscale // for onboarding key minting
	publicURL string
	mu        sync.Mutex
	sessions  map[string]*oauthSession
	onboard   *onboardRegistry
}

func newWebMux(g *Gateway, caDir string, ts Tailscale, publicURL string) http.Handler {
	w := &webMux{g: g, caDir: caDir, ts: ts, publicURL: publicURL, sessions: map[string]*oauthSession{}, onboard: g.onboard}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", w.serveInfo)
	mux.HandleFunc("/ca.crt", w.serveCA)
	mux.HandleFunc("/api/whoami", w.apiWhoami)
	mux.HandleFunc("/api/status", w.apiStatus)
	mux.HandleFunc("/api/agents", w.apiAgents)
	mux.HandleFunc("/api/agents/delete", w.apiAgentDelete)
	mux.HandleFunc("/api/agents/profile", w.apiAgentProfile)
	mux.HandleFunc("/api/profiles", w.apiProfiles)
	mux.HandleFunc("/api/rules", w.apiRules)
	mux.HandleFunc("/api/rules/device", w.apiDeviceRules)
	mux.HandleFunc("/api/rules/ai", w.apiRulesAI)
	mux.HandleFunc("/api/config", w.apiConfig)
	mux.HandleFunc("/api/hitl/pending", w.apiHITLPending)
	mux.HandleFunc("/api/hitl/decide", w.apiHITLDecide)
	mux.HandleFunc("/api/slack/interactive", w.apiSlackInteractive)
	mux.HandleFunc("/api/oauth/start", w.apiOAuthStart)
	mux.HandleFunc("/api/oauth/exchange", w.apiOAuthExchange)
	mux.HandleFunc("/api/oauth/device-poll", w.apiOAuthDevicePoll)
	mux.HandleFunc("/api/oauth/revoke", w.apiOAuthRevoke)
	mux.HandleFunc("/api/credentials/set", w.apiCredentialsSet)
	mux.HandleFunc("/api/credentials/clear", w.apiCredentialsClear)
	mux.HandleFunc("/api/events", w.apiEventsSSE)
	mux.HandleFunc("/api/onboard/start", w.apiOnboardStart)
	mux.HandleFunc("/api/onboard/poll", w.apiOnboardPoll)
	mux.HandleFunc("/api/onboard/approve", w.apiOnboardApprove)
	mux.HandleFunc("/api/onboard/lookup", w.apiOnboardLookup)
	mux.HandleFunc("/api/onboard/claim", w.apiOnboardClaim)
	mux.HandleFunc("/__login", w.apiDashboardLogin)
	mux.Handle("/", w.staticHandler())
	return w.dashboardSecretGate(w.tailnetGate(mux))
}

// dashboardSecretGate requires every non-public request to carry the
// configured dashboard_secret (cookie / header / query). Onboarding
// + health endpoints stay open so brand-new clients can still join.
//
// When dashboard_secret is empty, the gate's behavior depends on
// insecure_no_dashboard_secret: if that's true, the gate is a no-op
// (testing escape hatch); otherwise the gate refuses to serve and
// every gated route returns a misconfiguration error so an open
// dashboard isn't published by accident.
func (w *webMux) dashboardSecretGate(next http.Handler) http.Handler {
	publicPaths := map[string]bool{
		"/api/onboard/start":     true,
		"/api/onboard/poll":      true,
		"/api/onboard/claim":     true,
		"/api/onboard/lookup":    true,
		"/api/onboard/approve":   true,
		"/api/slack/interactive": true,
		"/info":                  true,
		"/ca.crt":                true,
		"/__login":               true,
	}
	// /info and /ca.crt are public-by-design (health + cert distribution).
	// They keep working even when the dashboard is misconfigured so
	// monitoring + already-onboarded clients aren't taken offline.
	alwaysOpen := map[string]bool{
		"/info":   true,
		"/ca.crt": true,
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		secret := w.g.cfg.DashboardSecret
		if secret == "" {
			if alwaysOpen[r.URL.Path] {
				next.ServeHTTP(rw, r)
				return
			}
			if w.g.cfg.InsecureNoDashboardSecret {
				next.ServeHTTP(rw, r)
				return
			}
			renderDashboardMisconfigured(rw, r)
			return
		}
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(rw, r)
			return
		}
		if checkDashboardSecret(r, secret) {
			next.ServeHTTP(rw, r)
			return
		}
		// API callers see 401; browsers get redirected to the login form.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(rw, "dashboard secret required", 401)
			return
		}
		http.Redirect(rw, r, "/__login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

const dashboardMisconfiguredMsg = "dashboard refuses to serve: gateway.hcl is missing both `dashboard_secret` and `insecure_no_dashboard_secret`. Set `dashboard_secret = \"<long random string>\"` to require a password, or `insecure_no_dashboard_secret = true` to explicitly run without auth (testing only)."

func renderDashboardMisconfigured(rw http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(rw, dashboardMisconfiguredMsg, http.StatusServiceUnavailable)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(rw, `<!doctype html>
<html><head><meta charset="utf-8"><title>clawpatrol — dashboard disabled</title>
<style>body{font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:42em;margin:6em auto;padding:0 1em;color:#222}code{background:#f3f3f3;padding:.1em .3em;border-radius:3px}h1{font-size:1.4em}</style>
</head><body>
<h1>Dashboard refuses to serve</h1>
<p>Your <code>gateway.hcl</code> sets neither <code>dashboard_secret</code> nor <code>insecure_no_dashboard_secret</code>, so the dashboard is locked to avoid being exposed without auth.</p>
<p>Pick one and reload (the gateway hot-reloads <code>gateway.hcl</code> within a few seconds):</p>
<ul>
<li><code>dashboard_secret = "&lt;long random string&gt;"</code> — production, requires a password.</li>
<li><code>insecure_no_dashboard_secret = true</code> — testing only, anyone who reaches this URL gets in.</li>
</ul>
</body></html>`)
}

func checkDashboardSecret(r *http.Request, want string) bool {
	if c, err := r.Cookie("cp_dash"); err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1 {
		return true
	}
	if h := r.Header.Get("X-Clawpatrol-Secret"); h != "" && subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
		return true
	}
	if q := r.URL.Query().Get("secret"); q != "" && subtle.ConstantTimeCompare([]byte(q), []byte(want)) == 1 {
		return true
	}
	return false
}

// apiDashboardLogin renders a one-field form (GET) and validates +
// sets the cp_dash cookie (POST). Plain HTML, no JS — keeps the
// login surface small.
func (w *webMux) apiDashboardLogin(rw http.ResponseWriter, r *http.Request) {
	want := w.g.cfg.DashboardSecret
	if want == "" {
		http.Redirect(rw, r, "/", http.StatusFound)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/"
	}
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(rw, "bad form", 400)
			return
		}
		got := r.PostFormValue("secret")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			renderLogin(rw, next, "wrong secret", 401)
			return
		}
		http.SetCookie(rw, &http.Cookie{
			Name:     "cp_dash",
			Value:    want,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   30 * 24 * 3600, // 30d
		})
		http.Redirect(rw, r, next, http.StatusFound)
		return
	}
	// GET — accept ?secret= one-shot to set the cookie automatically
	// (so an operator can paste a single URL with the secret).
	if q := r.URL.Query().Get("secret"); q != "" && subtle.ConstantTimeCompare([]byte(q), []byte(want)) == 1 {
		http.SetCookie(rw, &http.Cookie{
			Name:     "cp_dash",
			Value:    want,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   30 * 24 * 3600,
		})
		http.Redirect(rw, r, next, http.StatusFound)
		return
	}
	renderLogin(rw, next, "", 200)
}

func renderLogin(rw http.ResponseWriter, next, errMsg string, status int) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	_ = loginTpl.Execute(rw, struct{ Next, Error string }{next, errMsg})
}

// tailnetGate restricts non-tailnet callers to a minimal allow-list
// needed for `clawpatrol join` device-flow onboarding. Dashboard, status,
// oauth and event streams are tailnet-only.
//
// Public allow-list:
//
//	POST /api/onboard/start    — kicks off device flow
//	POST /api/onboard/poll     — CLI polls for approval + auth key
//	GET  /info                 — health check
func (w *webMux) tailnetGate(next http.Handler) http.Handler {
	publicPaths := map[string]bool{
		"/api/onboard/start":     true,
		"/api/onboard/poll":      true,
		"/api/onboard/claim":     true, // device_code-gated; safe to be public
		"/api/slack/interactive": true, // signed payload; verified via slack signing secret
		"/info":                  true,
		"/ca.crt":                true, // gateway's public CA cert, intentionally exposed
	}
	// In wireguard / proxy mode there is no tailnet identity to gate
	// against. Operators put the dashboard behind their own
	// authentication (Cloudflare Access, basic auth proxy, etc).
	skipGate := !strings.EqualFold(w.g.cfg.Tailscale.Control, "tailscale") &&
		w.g.cfg.Tailscale.Control != ""

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if publicPaths[r.URL.Path] || skipGate {
			next.ServeHTTP(rw, r)
			return
		}
		// Two ways to prove tailnet membership:
		//   1. peer IP whois (direct tailnet → gateway, no proxy).
		//   2. Tailscale-User-Login header from `tailscale serve` —
		//      ONLY trusted when the proxy hop is local (127.0.0.1 /
		//      ::1). Anyone hitting us via funnel can otherwise forge
		//      the header trivially.
		host := r.RemoteAddr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		var login string
		if w.g.agents != nil {
			if who := w.g.agents.lookupWhois(host); who != nil {
				login = who.UserProfile.LoginName
			}
		}
		if login == "" && isLoopback(host) {
			// `tailscale serve` proxy hop. The header is authoritative
			// here because nothing public can reach loopback.
			login = r.Header.Get("Tailscale-User-Login")
		}
		if login == "" {
			http.Error(rw, "tailnet access required — onboard via `clawpatrol join --url <gateway>`", 403)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *webMux) staticHandler() http.Handler {
	sub, err := fs.Sub(dashboardFS, "www/dist")
	if err != nil {
		return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "dashboard not built (cd www && npm run build)", 500)
		})
	}
	return http.FileServer(http.FS(sub))
}

func (w *webMux) serveCA(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/x-pem-file")
	http.ServeFile(rw, r, w.caDir+"/ca.crt")
}

func (w *webMux) serveInfo(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(rw, `{"clawpatrol":true,"version":"0.1"}`+"\n")
}

// callerIdentity resolves the (user, device) of the request peer via
// tailscale whois. May be empty if Tailscale is not available.
func (w *webMux) callerIdentity(r *http.Request) (user, device, displayHost string) {
	host := r.Header.Get("X-Forwarded-For")
	if host == "" {
		ipPort := r.RemoteAddr
		if i := strings.LastIndex(ipPort, ":"); i >= 0 {
			host = ipPort[:i]
		} else {
			host = ipPort
		}
	}
	if w.g.agents == nil {
		return "", "", host
	}
	who := w.g.agents.lookupWhois(host)
	if who == nil {
		return "", "", host
	}
	return who.UserProfile.LoginName, who.Node.StableID, who.Node.HostName
}

// ownerForCaller returns the credential-bucket key for a dashboard
// request. With the profile-as-tenant model, that key is the profile
// name selected by the operator — passed via `?profile=<name>` query
// param or the `X-Clawpatrol-Profile` header. Falls back to the first
// declared profile in gateway.hcl, or admin_email when no profiles
// are configured (legacy single-tenant mode).
func (w *webMux) ownerForCaller(r *http.Request) (key, label string) {
	if p := r.URL.Query().Get("profile"); p != "" {
		return p, p
	}
	if p := r.Header.Get("X-Clawpatrol-Profile"); p != "" {
		return p, p
	}
	if names := orderedProfileNames(w.g.cfg.Policy); len(names) > 0 {
		return names[0], names[0]
	}
	if w.g.cfg.AdminEmail != "" {
		return w.g.cfg.AdminEmail, w.g.cfg.AdminEmail
	}
	user, _, host := w.callerIdentity(r)
	if user != "" {
		return user, user
	}
	return host, host
}

func (w *webMux) apiWhoami(rw http.ResponseWriter, r *http.Request) {
	user, device, host := w.callerIdentity(r)
	// Read public_url straight from the live config so that an
	// operator editing gateway.hcl sees the new value reflected
	// without a gateway restart (mtime watcher swaps cfg).
	pu := w.g.cfg.PublicURL
	if pu == "" {
		pu = w.publicURL
	}
	writeJSON(rw, map[string]string{
		"user":       user,
		"device":     device,
		"host":       host,
		"public_url": pu,
	})
}

// apiStatus returns the credentials list for the dashboard. Filters
// by profile when ?profile=NAME is set — only credentials referenced
// by an endpoint in that profile come back. Without the param, every
// declared credential ships (root view).
func (w *webMux) apiStatus(rw http.ResponseWriter, r *http.Request) {
	out := []IntegrationRow{}
	policy := w.g.policy.Load()
	if policy == nil {
		writeJSON(rw, out)
		return
	}
	profile := r.URL.Query().Get("profile")
	allowed := credentialsInProfile(policy, profile) // nil = no filter

	names := make([]string, 0, len(policy.Credentials))
	for name := range policy.Credentials {
		if allowed != nil && !allowed[name] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	caller, _ := w.ownerForCaller(r)
	for _, name := range names {
		ent := policy.Credentials[name]
		row := IntegrationRow{ID: name, Name: name, Type: ent.Plugin.Type}
		if _, ok := ent.Body.(config.OAuthFlowProvider); ok {
			row.HasOAuth = true
			for _, owner := range w.g.oauth.Owners(name) {
				connected, exp := w.g.oauth.Status(name, owner)
				o := Owner{Owner: owner, Connected: connected}
				if !exp.IsZero() {
					o.ExpiresAt = exp.Unix()
				}
				row.Owners = append(row.Owners, o)
			}
		}
		if sp, ok := ent.Body.(config.SecretSlotsProvider); ok {
			row.Slots = sp.SecretSlots()
			if caller != "" {
				present, _ := credentialSlotPresence(w.g.db, name, caller)
				if len(present) > 0 {
					row.Owners = append(row.Owners, Owner{Owner: caller, Connected: true})
				}
			}
		}
		out = append(out, row)
	}
	writeJSON(rw, out)
}

// credentialsInProfile returns the set of credential bare names that
// any endpoint in the given profile references. nil means "no filter
// — return everything." Used by apiStatus and the device-page card
// render so per-device views only show credentials the device's
// profile actually uses.
func credentialsInProfile(policy *config.CompiledPolicy, profile string) map[string]bool {
	if profile == "" || policy == nil {
		return nil
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		return map[string]bool{} // unknown profile → empty set, not nil
	}
	out := map[string]bool{}
	for _, ep := range prof.Endpoints {
		for _, cb := range ep.Credentials {
			if cb.Credential != nil {
				out[cb.Credential.Symbol.Name] = true
			}
		}
	}
	return out
}

// apiCredentialsSet persists one or more slot values for a non-OAuth
// credential. Owner defaults to the caller's profile. Body shape:
//
//	{ "id": "stripe-live", "owner": "default", "slots": { "": "sk_live_…" } }
//
// Multi-slot credentials (mtls, slack tokens) pass multiple keys.
// Empty values clear the slot.
func (w *webMux) apiCredentialsSet(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	var body struct {
		ID    string            `json:"id"`
		Owner string            `json:"owner"`
		Slots map[string]string `json:"slots"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	if body.Owner == "" {
		body.Owner, _ = w.ownerForCaller(r)
	}
	if body.Owner == "" {
		http.Error(rw, "missing owner", 400)
		return
	}
	policy := w.g.policy.Load()
	ent, ok := policy.Credentials[body.ID]
	if !ok {
		http.Error(rw, "unknown credential: "+body.ID, 404)
		return
	}
	sp, ok := ent.Body.(config.SecretSlotsProvider)
	if !ok {
		http.Error(rw, "credential is OAuth-flow, use /api/oauth/start", 400)
		return
	}
	valid := map[string]bool{}
	for _, s := range sp.SecretSlots() {
		valid[s.Name] = true
	}
	for slot, v := range body.Slots {
		if !valid[slot] {
			http.Error(rw, "unknown slot: "+slot, 400)
			return
		}
		if v == "" {
			// Empty value = clear that slot specifically.
			if _, err := w.g.db.Exec(
				`DELETE FROM credential_secrets WHERE credential = ? AND profile = ? AND slot = ?`,
				body.ID, body.Owner, slot,
			); err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
			continue
		}
		if err := setCredentialSlot(w.g.db, body.ID, body.Owner, slot, v); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// apiCredentialsClear drops every slot for (id, owner). Disconnect
// button on the dashboard.
func (w *webMux) apiCredentialsClear(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	var body struct {
		ID    string `json:"id"`
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	if body.Owner == "" {
		body.Owner, _ = w.ownerForCaller(r)
	}
	if err := clearCredentialSecrets(w.g.db, body.ID, body.Owner); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// lookupOAuthFlow finds the OAuth flow for a credential bare name in
// the loaded policy. Returns nil when the credential doesn't exist or
// the credential type isn't an OAuth-flow type.
func lookupOAuthFlow(policy *config.CompiledPolicy, name string) *config.OAuthIntegration {
	if policy == nil {
		return nil
	}
	ent, ok := policy.Credentials[name]
	if !ok {
		return nil
	}
	fp, ok := ent.Body.(config.OAuthFlowProvider)
	if !ok {
		return nil
	}
	return fp.OAuthFlow()
}

func (w *webMux) apiAgents(rw http.ResponseWriter, _ *http.Request) {
	var snap []*Agent
	if w.g.agents != nil {
		snap = w.g.agents.snapshot()
	}
	// External IPs: the underlay v4/v6 each WG peer is dialing in from.
	// Show these in place of the server-side /32 (routing artefact).
	// Live endpoint observed via wg-go IpcGet — persist into the devices
	// row so the dashboard keeps a stable last-known address even when
	// the peer goes idle and wg-go drops its endpoint state.
	if globalWG != nil {
		for ip, ep := range globalWG.EndpointsByIP() {
			if ep == "" {
				continue
			}
			parsed := net.ParseIP(ep)
			var v4, v6 string
			if p4 := parsed.To4(); p4 != nil {
				v4 = p4.String()
			} else if parsed != nil {
				v6 = parsed.String()
			}
			w.onboard.SetExternalIPs(ip, v4, v6)
		}
	}
	for _, a := range snap {
		v4, v6 := w.onboard.ExternalIPs(a.IP)
		a.ExternalIPv4, a.ExternalIPv6 = v4, v6
	}
	// enrich with connected integrations per agent's user. Re-run on
	// every snapshot — caching by `Integrations != nil` would freeze
	// the list at first sighting (a freshly-onboarded device whose
	// user later connects Claude wouldn't reflect the new connection).
	for _, a := range snap {
		// Per-profile credentials: the agent's Integrations list
		// reflects what the device's bound profile has connected. Falls
		// back to the legacy per-user lookup for tailnet-control-mode
		// installs that still bucket creds by login.
		profile := w.onboard.ProfileForIP(a.IP)
		if profile == "" {
			if a.User == "" || a.User == "tagged-devices" {
				if owner := w.onboard.OwnerForIP(a.IP); owner != "" {
					a.User = owner
				}
			}
			profile = a.User
		}
		if profile == "" {
			continue
		}
		// Walk every declared credential — connected if either an
		// OAuth token exists OR the operator pasted a secret slot via
		// the dashboard. Was hardcoded to the claude/codex/github
		// legacy trio, which silently hid every other credential type
		// from the agents table.
		var ids []string
		if policy := w.g.Policy(); policy != nil {
			names := make([]string, 0, len(policy.Credentials))
			for name := range policy.Credentials {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if conn, _ := w.g.oauth.Status(name, profile); conn {
					ids = append(ids, name)
					continue
				}
				present, _ := credentialSlotPresence(w.g.db, name, profile)
				if len(present) > 0 {
					ids = append(ids, name)
				}
			}
		}
		if ids != nil {
			a.Integrations = ids
		}
	}
	writeJSON(rw, snap)
}

// apiAgentDelete drops a device from clawpatrol's view. Removes the
// in-memory agent record, the onboard owner / hostname / profile
// row, and (in WG mode) the WireGuard peer + allowed-IP entry — so
// traffic from the deleted device's tunnel can't keep flowing under
// the old owner. The Tailscale node itself isn't kicked; admins do
// that from the Tailscale admin console.
func (w *webMux) apiAgentDelete(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(rw, "missing ip", 400)
		return
	}
	if w.g.agents != nil {
		w.g.agents.Delete(ip)
	}
	if w.g.onboard != nil {
		w.g.onboard.ForgetIP(ip)
	}
	if globalWG != nil {
		globalWG.RevokePeerByIP(ip)
	}
	writeJSON(rw, map[string]bool{"ok": true})
}

// apiAgentProfile assigns a peer IP to a named profile. Profile must
// be declared in cfg.Profiles. The mapping is persisted in
// onboard.profileByIP and consulted by Gateway.profileFor at MITM
// time, so rule scoping switches over immediately.
func (w *webMux) apiAgentProfile(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	ip := r.URL.Query().Get("ip")
	profile := r.URL.Query().Get("profile")
	if ip == "" || profile == "" {
		http.Error(rw, "missing ip or profile", 400)
		return
	}
	names := orderedProfileNames(w.g.cfg.Policy)
	known := false
	for _, n := range names {
		if n == profile {
			known = true
			break
		}
	}
	if !known {
		http.Error(rw, "unknown profile", 400)
		return
	}
	w.g.onboard.AssignProfile(ip, profile)
	writeJSON(rw, map[string]any{"ok": true, "ip": ip, "profile": profile})
}

// apiProfiles lists declared profile names so the dashboard can
// render a profile picker per device.
func (w *webMux) apiProfiles(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, orderedProfileNames(w.g.cfg.Policy))
}

// RuleSummary is the JSON shape the dashboard renders for each rule.
// It flattens a CompiledRule plus its enclosing endpoint and profile
// context so the table view doesn't need to walk the policy graph
// itself.
type RuleSummary struct {
	Name     string                `json:"name"`
	Family   string                `json:"family"` // "https" | "sql" | "k8s"
	Endpoint string                `json:"endpoint"`
	Profile  string                `json:"profile,omitempty"`
	DeviceIP string                `json:"device_ip,omitempty"` // "" for profile rules, IP for device-pinned
	Priority int                   `json:"priority,omitempty"`
	Disabled bool                  `json:"disabled,omitempty"`
	Match    map[string]any        `json:"match,omitempty"`
	Verdict  string                `json:"verdict,omitempty"`
	Reason   string                `json:"reason,omitempty"`
	Approve  []config.ApproveStage `json:"approve,omitempty"`
}

// apiRules returns every compiled rule across every profile, flattened
// for the dashboard table view. Rules attached to multiple endpoints
// emit one row per endpoint so the operator sees each attachment
// site individually.
//
// Read-only. Edits go through PUT /api/config (whole-file HCL via
// the new typed-block validator).
func (w *webMux) apiRules(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(rw, w.collectRuleSummaries(""))
	default:
		http.Error(rw, "edit rules through PUT /api/config", http.StatusNotImplemented)
	}
}

// apiDeviceRules returns the rules that apply to one device. The
// device's profile is read from g.profileFor(ip); rules are filtered
// to endpoints declared in that profile.
//
// Read-only — same as apiRules.
func (w *webMux) apiDeviceRules(rw http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(rw, "missing ip", 400)
		return
	}
	hclMode := r.URL.Query().Get("format") == "hcl"
	switch r.Method {
	case "GET":
		if hclMode {
			body, err := readDeviceBlockHCL(w.g.cfgPath, ip)
			if err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rw.Write([]byte(body))
			return
		}
		profile := w.g.profileFor(ip)
		writeJSON(rw, w.collectRuleSummariesForDevice(profile, ip))
	case "PUT":
		if !hclMode {
			http.Error(rw, "PUT requires ?format=hcl", 400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		// Splice the new device block into gateway.hcl, then validate
		// the merged file via the typed-block loader before persisting
		// — same diagnostic path as PUT /api/config.
		merged, err := spliceDeviceBlockHCL(w.g.cfgPath, ip, string(body))
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		if _, diags := config.LoadBytes(merged, "gateway.hcl"); diags.HasErrors() {
			http.Error(rw, "hcl: "+diags.Error(), 400)
			return
		}
		tmp := w.g.cfgPath + ".tmp"
		if err := os.WriteFile(tmp, merged, 0o600); err != nil {
			http.Error(rw, "write: "+err.Error(), 500)
			return
		}
		if err := os.Rename(tmp, w.g.cfgPath); err != nil {
			http.Error(rw, "rename: "+err.Error(), 500)
			return
		}
		writeJSON(rw, map[string]any{"ok": true})
	default:
		http.Error(rw, "GET or PUT", 405)
	}
}

// collectRuleSummariesForDevice yields the same set as
// collectRuleSummaries(profileFilter) PLUS every device-pinned rule
// whose DeviceIP matches the device — even when the rule's endpoint
// isn't part of that device's profile (the AI may declare a new
// endpoint inside a device fragment that doesn't get added to the
// profile until later).
func (w *webMux) collectRuleSummariesForDevice(profile, deviceIP string) []RuleSummary {
	out := w.collectRuleSummaries(profile)
	policy := w.g.Policy()
	if policy == nil {
		return out
	}
	seen := map[string]bool{}
	for _, s := range out {
		seen[s.Endpoint+"\x00"+s.Name] = true
	}
	for epName, ep := range policy.Endpoints {
		for _, r := range ep.Rules {
			if r.DeviceIP != deviceIP {
				continue
			}
			key := epName + "\x00" + r.Name
			if seen[key] {
				continue
			}
			out = append(out, RuleSummary{
				Name:     r.Name,
				Family:   ep.Family,
				Endpoint: epName,
				DeviceIP: r.DeviceIP,
				Priority: r.Priority,
				Disabled: r.Disabled,
				Match:    matchSourceMap(r),
				Verdict:  r.Outcome.Verdict,
				Reason:   r.Outcome.Reason,
				Approve:  r.Outcome.Approve,
			})
		}
	}
	return out
}

// collectRuleSummaries walks the compiled policy and emits one
// RuleSummary per (rule × endpoint × profile) triple. When profile is
// empty, every profile contributes; otherwise only that profile.
//
// Sort: by profile, then endpoint, then descending priority (so the
// dashboard mirrors first-match-wins order within each endpoint).
func (w *webMux) collectRuleSummaries(profileFilter string) []RuleSummary {
	policy := w.g.Policy()
	if policy == nil {
		return []RuleSummary{}
	}
	var out []RuleSummary
	for profileName, prof := range policy.Profiles {
		if profileFilter != "" && profileName != profileFilter {
			continue
		}
		for epName, ep := range prof.Endpoints {
			for _, r := range ep.Rules {
				out = append(out, RuleSummary{
					Name:     r.Name,
					Family:   ep.Family,
					Endpoint: epName,
					Profile:  profileName,
					DeviceIP: r.DeviceIP,
					Priority: r.Priority,
					Disabled: r.Disabled,
					Match:    matchSourceMap(r),
					Verdict:  r.Outcome.Verdict,
					Reason:   r.Outcome.Reason,
					Approve:  r.Outcome.Approve,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Profile != out[j].Profile {
			return out[i].Profile < out[j].Profile
		}
		if out[i].Endpoint != out[j].Endpoint {
			return out[i].Endpoint < out[j].Endpoint
		}
		return out[i].Priority > out[j].Priority
	})
	return out
}

func matchSourceMap(r *config.CompiledRule) map[string]any {
	if r == nil {
		return nil
	}
	return r.Match
}

// apiConfig serves the entire gateway.hcl for the global settings
// editor. GET returns the file as-is (preserves operator comments).
// PUT validates by re-parsing + writing through writeConfigHCL so
// hot-reload picks up the change.
func (w *webMux) apiConfig(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		b, err := os.ReadFile(w.g.cfgPath)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rw.Write(b)
	case "PUT":
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		// Validate via the new typed-block loader before persisting —
		// rejects unknown attributes / dangling references / kind
		// mismatches with precise diagnostics.
		if _, diags := config.LoadBytes(body, "gateway.hcl"); diags.HasErrors() {
			http.Error(rw, "hcl: "+diags.Error(), 400)
			return
		}
		// atomic write — mtime watcher reloads + applies.
		tmp := w.g.cfgPath + ".tmp"
		if err := os.WriteFile(tmp, body, 0o600); err != nil {
			http.Error(rw, "write: "+err.Error(), 500)
			return
		}
		if err := os.Rename(tmp, w.g.cfgPath); err != nil {
			http.Error(rw, "rename: "+err.Error(), 500)
			return
		}
		writeJSON(rw, map[string]any{"ok": true, "bytes": len(body)})
	default:
		http.Error(rw, "GET or PUT", 405)
	}
}

// apiRulesAI translates a natural-language request into an HCL rule
// edit using a connected LLM provider. POST body:
//
//	{prompt, current_yaml, scope: "device"|"global", agent: "claude"|"codex"}
//
// Returns: {yaml: <suggested>}. (Wire field names stay as
// `current_yaml`/`yaml` for backward compat with existing dashboard
// builds — the contents are HCL.)
func (w *webMux) apiRulesAI(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	var body struct {
		Prompt      string `json:"prompt"`
		CurrentYAML string `json:"current_yaml"`
		Scope       string `json:"scope"`
		Agent       string `json:"agent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.Prompt == "" {
		http.Error(rw, "prompt required", 400)
		return
	}
	owner, _ := w.ownerForCaller(r)
	if owner == "" {
		http.Error(rw, "tailnet identity required", 403)
		return
	}
	out, refused, err := generateRuleHCL(r.Context(), w.g, body.Agent, owner, body.Prompt, body.CurrentYAML, body.Scope)
	if err != nil {
		http.Error(rw, "ai: "+err.Error(), 502)
		return
	}
	resp := map[string]string{"yaml": out}
	if refused != "" {
		resp["refused"] = refused
	}
	writeJSON(rw, resp)
}

func (w *webMux) apiHITLPending(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, w.g.hitl.List())
}

func (w *webMux) apiHITLDecide(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	var body struct {
		ID    string `json:"id"`
		Allow bool   `json:"allow"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	owner, _ := w.ownerForCaller(r)
	ok := w.g.hitl.Decide(body.ID, runtime.HITLDecision{Allow: body.Allow, By: owner})
	writeJSON(rw, map[string]bool{"ok": ok})
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "127.")
}

func (w *webMux) apiOAuthStart(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	id := r.URL.Query().Get("id")
	flow := lookupOAuthFlow(w.g.policy.Load(), id)
	if flow == nil {
		http.Error(rw, "no oauth integration: "+id, 400)
		return
	}
	owner, ownerLabel := w.ownerForCaller(r)
	if owner == "" {
		http.Error(rw, "could not determine owner identity (tailscale whois failed)", 400)
		return
	}
	// Branch: device flow vs auth-code+PKCE.
	if flow.Flow == "device" {
		w.startDeviceFlow(rw, id, flow, owner, ownerLabel)
		return
	}

	verifier := randomString(64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomString(32)
	cfg := &oauth2.Config{
		ClientID:     resolveTemplate(flow.OAuth.ClientID),
		ClientSecret: resolveTemplate(flow.OAuth.ClientSecret),
		Scopes:       flow.OAuth.Scopes,
		RedirectURL:  flow.OAuth.RedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: flow.OAuth.AuthURL, TokenURL: flow.OAuth.TokenURL},
	}
	authURL := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{verifier: verifier, state: state, cfg: cfg, id: id, owner: owner, created: time.Now()}
	for k, s := range w.sessions {
		if time.Since(s.created) > 10*time.Minute {
			delete(w.sessions, k)
		}
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]string{"auth_url": authURL, "state": state, "owner": ownerLabel})
}

func (w *webMux) apiOAuthExchange(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	var body struct {
		State string `json:"state"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	body.Code = strings.TrimSpace(body.Code)
	if body.Code == "" || body.State == "" {
		http.Error(rw, "missing code/state", 400)
		return
	}
	if i := strings.IndexAny(body.Code, "#&?"); i > 0 {
		body.Code = body.Code[:i]
	}

	w.mu.Lock()
	sess, ok := w.sessions[body.State]
	if ok {
		delete(w.sessions, body.State)
	}
	w.mu.Unlock()
	if !ok {
		http.Error(rw, "unknown state (expired or stale)", 400)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tok, err := exchangeOAuthCode(ctx, sess, body.Code, body.State)
	if err != nil {
		http.Error(rw, "token exchange: "+err.Error(), 400)
		return
	}
	if err := w.g.oauth.Set(sess.id, sess.owner, tok); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"connected": true, "owner": sess.owner, "expires": tok.Expiry.Unix()})
}

// startDeviceFlow kicks off OAuth device flow (RFC 8628). Returns
// {user_code, verification_uri, device_code, interval} so the dashboard
// can prompt the user to enter the code at the verification URI.
func (w *webMux) startDeviceFlow(rw http.ResponseWriter, id string, it *OAuthIntegration, owner, ownerLabel string) {
	form := url.Values{}
	form.Set("client_id", resolveTemplate(it.OAuth.ClientID))
	if len(it.OAuth.Scopes) > 0 {
		form.Set("scope", strings.Join(it.OAuth.Scopes, " "))
	}
	req, _ := http.NewRequest("POST", it.OAuth.DeviceURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "device-code: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		http.Error(rw, fmt.Sprintf("device-code %d: %s", resp.StatusCode, string(body)), 502)
		return
	}
	var dr struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &dr); err != nil {
		http.Error(rw, "device-code parse: "+err.Error(), 502)
		return
	}
	state := randomString(32)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		state:    state,
		id:       id,
		owner:    owner,
		created:  time.Now(),
		verifier: dr.DeviceCode, // reuse field for device_code
		cfg: &oauth2.Config{
			ClientID: resolveTemplate(it.OAuth.ClientID),
			Endpoint: oauth2.Endpoint{TokenURL: it.OAuth.TokenURL},
		},
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]any{
		"flow":             "device",
		"state":            state,
		"user_code":        dr.UserCode,
		"verification_uri": dr.VerificationURI,
		"interval":         dr.Interval,
		"expires_in":       dr.ExpiresIn,
		"owner":            ownerLabel,
	})
}

// pollDeviceFlow exchanges device_code for a token. Called by the
// frontend on a timer until success / denial / expiration.
func (w *webMux) pollDeviceFlow(rw http.ResponseWriter, sess *oauthSession) {
	form := url.Values{}
	form.Set("client_id", sess.cfg.ClientID)
	form.Set("device_code", sess.verifier)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	req, _ := http.NewRequest("POST", sess.cfg.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "device poll: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// Don't log the body verbatim — on success it carries access_token.
	var tr struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		RefreshToken     string `json:"refresh_token"`
		Scope            string `json:"scope"`
		ExpiresIn        int64  `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Interval         int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		http.Error(rw, "device poll parse: "+err.Error(), 502)
		return
	}
	if tr.Error != "" {
		// `slow_down` carries an updated interval (RFC 8628). Surface
		// it to the dashboard so the polling loop respects the new
		// cadence; otherwise the client keeps hitting at the original
		// interval and GitHub never returns the token.
		out := map[string]any{"error": tr.Error, "detail": tr.ErrorDescription}
		if tr.Interval > 0 {
			out["interval"] = tr.Interval
		}
		writeJSON(rw, out)
		return
	}
	if tr.AccessToken == "" {
		writeJSON(rw, map[string]string{"error": "authorization_pending"})
		return
	}
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	w.mu.Lock()
	delete(w.sessions, sess.state)
	w.mu.Unlock()
	if err := w.g.oauth.Set(sess.id, sess.owner, tok); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"connected": true, "owner": sess.owner})
}

// exchangeOAuthCode finalizes an OAuth PKCE flow. Anthropic's token
// endpoint requires a JSON body (returns "Invalid request format" for
// the standard form-urlencoded body), so we hand-roll the request for
// claude integration. Other providers use the stdlib oauth2.Exchange.
func exchangeOAuthCode(ctx context.Context, sess *oauthSession, code, state string) (*oauth2.Token, error) {
	if sess.id == "claude" {
		return exchangeAnthropicCode(ctx, sess, code, state)
	}
	return sess.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", sess.verifier),
		oauth2.SetAuthURLParam("redirect_uri", sess.cfg.RedirectURL),
	)
}

func exchangeAnthropicCode(ctx context.Context, sess *oauthSession, code, state string) (*oauth2.Token, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  sess.cfg.RedirectURL,
		"client_id":     sess.cfg.ClientID,
		"code_verifier": sess.verifier,
		"state":         state,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", sess.cfg.Endpoint.TokenURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(respBytes))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(respBytes, &tr); err != nil {
		return nil, err
	}
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tok, nil
}

func (w *webMux) apiOAuthDevicePoll(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	state := r.URL.Query().Get("state")
	w.mu.Lock()
	sess := w.sessions[state]
	w.mu.Unlock()
	if sess == nil {
		http.Error(rw, "unknown state (expired)", 400)
		return
	}
	w.pollDeviceFlow(rw, sess)
}

func (w *webMux) apiOAuthRevoke(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	var body struct {
		ID    string `json:"id"`
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" || body.Owner == "" {
		http.Error(rw, "missing id or owner", 400)
		return
	}
	w.g.oauth.Revoke(body.ID, body.Owner)
	writeJSON(rw, map[string]bool{"ok": true})
}

func (w *webMux) apiEventsSSE(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", 500)
		return
	}

	wantIP := r.URL.Query().Get("agent")

	if w.g.sink == nil {
		fmt.Fprintf(rw, ": no sink\n\n")
		flusher.Flush()
		return
	}
	backlog, ch, cancel := w.g.sink.RecentAndSubscribe()
	defer cancel()

	fmt.Fprint(rw, ": connected\n\n")
	// Replay backlog (oldest → newest) so a refreshed dashboard sees the
	// last few hundred events instead of an empty stream. Frontend
	// prepends each event, so newest still ends up at the top.
	for _, ev := range backlog {
		if wantIP != "" && ev.AgentIP != wantIP {
			continue
		}
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		fmt.Fprintf(rw, "data: %s\n\n", b)
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(rw, ": ka\n\n")
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if wantIP != "" && ev.AgentIP != wantIP {
				continue
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(rw, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(v)
}

// apiOnboardStart begins device-flow onboarding. Public (no auth)
// since this IS how a brand-new client first contacts the gateway.
// The returned user_code must still be approved by an existing tailnet
// member on the dashboard.
func (w *webMux) apiOnboardStart(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	s := w.onboard.start()
	// CLI passes its os.Hostname() so the dashboard shows a real
	// device name instead of just the WG-side IP. Optional — we still
	// fall back gracefully when missing.
	if hn := strings.TrimSpace(r.URL.Query().Get("hostname")); hn != "" {
		w.onboard.mu.Lock()
		s.hostname = hn
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
	// Operator picks which profile this device joins. Falls back to the
	// first declared profile when the dashboard didn't pass one.
	profile := r.URL.Query().Get("profile")
	if profile == "" {
		if names := orderedProfileNames(w.g.cfg.Policy); len(names) > 0 {
			profile = names[0]
		}
	}
	s := w.onboard.byUserCode(code)
	if s == nil {
		http.Error(rw, "unknown or expired code", 404)
		return
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

func allIntegrationKeys() []string { return displayOrder }

// Event sink + sampling helpers (fed by g.handle/mitm/splice; consumed
// by the dashboard SSE stream and the on-disk event log).

type Event struct {
	Ts         time.Time `json:"ts"`
	Mode       string    `json:"mode"`
	Agent      string    `json:"agent,omitempty"`
	AgentIP    string    `json:"agent_ip,omitempty"`
	Host       string    `json:"host"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Status     int       `json:"status,omitempty"`
	In         int64     `json:"in,omitempty"`
	Out        int64     `json:"out,omitempty"`
	Ms         int64     `json:"ms"`
	Action     string    `json:"action,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	ReqSha     string    `json:"req_sha,omitempty"`
	ReqSample  string    `json:"req_sample,omitempty"`
	RespSha    string    `json:"resp_sha,omitempty"`
	RespSample string    `json:"resp_sample,omitempty"`
}

type Sink struct {
	ch        chan Event
	db        *sql.DB
	drops     atomic.Uint64
	mu        sync.Mutex
	subs      []chan Event
	recent    []Event // ring of recent events for backlog replay
	recentCap int
}

func NewSink(db *sql.DB, buf int) (*Sink, error) {
	s := &Sink{ch: make(chan Event, buf), db: db, recentCap: 500}
	if db != nil {
		if seed, err := readTailEvents(db, s.recentCap); err == nil && len(seed) > 0 {
			s.recent = seed
		}
	}
	go s.drain()
	return s, nil
}

func readTailEvents(db *sql.DB, n int) ([]Event, error) {
	rows, err := db.Query(`
		SELECT ts_ns, mode, agent_ip, host, method, path, status,
		       bytes_in, bytes_out, ms, action, reason, req_sha, resp_sha
		FROM actions ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Event, 0, n)
	for rows.Next() {
		var (
			e       Event
			tsNs    int64
			mode    sql.NullString
			agentIP sql.NullString
			method  sql.NullString
			path    sql.NullString
			status  sql.NullInt64
			in, ot  sql.NullInt64
			ms      sql.NullInt64
			action  sql.NullString
			reason  sql.NullString
			reqSha  sql.NullString
			respSha sql.NullString
		)
		if err := rows.Scan(&tsNs, &mode, &agentIP, &e.Host, &method, &path, &status, &in, &ot, &ms, &action, &reason, &reqSha, &respSha); err != nil {
			return nil, err
		}
		e.Ts = time.Unix(0, tsNs).UTC()
		e.Mode = mode.String
		e.AgentIP = agentIP.String
		e.Method = method.String
		e.Path = path.String
		e.Status = int(status.Int64)
		e.In = in.Int64
		e.Out = ot.Int64
		e.Ms = ms.Int64
		e.Action = action.String
		e.Reason = reason.String
		e.ReqSha = reqSha.String
		e.RespSha = respSha.String
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// rows are newest-first; flip to oldest-first so SSE backlog
	// arrives in the order subscribers expect.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *Sink) Emit(e Event) {
	if s == nil {
		return
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	select {
	case s.ch <- e:
	default:
		s.drops.Add(1)
	}
}

func (s *Sink) Drops() uint64 { return s.drops.Load() }

func (s *Sink) drain() {
	for e := range s.ch {
		if s.db != nil {
			_, _ = s.db.Exec(`
				INSERT INTO actions
				 (ts_ns, mode, agent_ip, host, method, path, status, bytes_in, bytes_out, ms, action, reason, req_sha, resp_sha)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			`, e.Ts.UnixNano(), e.Mode, e.AgentIP, e.Host, e.Method, e.Path, e.Status, e.In, e.Out, e.Ms, e.Action, e.Reason, e.ReqSha, e.RespSha)
		}
		s.mu.Lock()
		s.recent = append(s.recent, e)
		if len(s.recent) > s.recentCap {
			s.recent = s.recent[len(s.recent)-s.recentCap:]
		}
		for _, sub := range s.subs {
			select {
			case sub <- e:
			default:
				// slow consumer; drop
			}
		}
		s.mu.Unlock()
	}
}

// RecentAndSubscribe atomically snapshots the backlog and registers a
// subscriber under the same lock so no event is missed or duplicated
// between the two. Caller should write the snapshot first, then loop on
// the channel for new events.
func (s *Sink) RecentAndSubscribe() ([]Event, <-chan Event, func()) {
	if s == nil {
		ch := make(chan Event)
		close(ch)
		return nil, ch, func() {}
	}
	ch := make(chan Event, 64)
	s.mu.Lock()
	snap := append([]Event(nil), s.recent...)
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}
	return snap, ch, cancel
}

func (s *Sink) Subscribe() (<-chan Event, func()) {
	_, ch, cancel := s.RecentAndSubscribe()
	return ch, cancel
}

type sampler struct {
	hash hash.Hash
	cap  int
	buf  bytes.Buffer
	n    int64
}

func newSampler(capBytes int) *sampler {
	return &sampler{hash: sha256.New(), cap: capBytes}
}

func (s *sampler) Write(p []byte) (int, error) {
	s.hash.Write(p)
	s.n += int64(len(p))
	if remain := s.cap - s.buf.Len(); remain > 0 {
		take := len(p)
		if take > remain {
			take = remain
		}
		s.buf.Write(p[:take])
	}
	return len(p), nil
}

func (s *sampler) sha() string {
	if s.n == 0 {
		return ""
	}
	return hex.EncodeToString(s.hash.Sum(nil))
}

func (s *sampler) sample() string {
	if s.buf.Len() == 0 {
		return ""
	}
	if isPrintable(s.buf.Bytes()) {
		return s.buf.String()
	}
	return "binary:" + hex.EncodeToString(s.buf.Bytes()[:min(64, s.buf.Len())])
}

func isPrintable(b []byte) bool {
	for _, x := range b {
		if x == 0 || (x < 0x20 && x != '\n' && x != '\r' && x != '\t') {
			return false
		}
	}
	return true
}

type teeReadCloser struct {
	r io.Reader
	c io.Closer
}

func (t teeReadCloser) Read(p []byte) (int, error) { return t.r.Read(p) }
func (t teeReadCloser) Close() error               { return t.c.Close() }

func wrapBodySampler(rc io.ReadCloser, s *sampler) io.ReadCloser {
	if rc == nil {
		return nil
	}
	return teeReadCloser{r: io.TeeReader(rc, s), c: rc}
}

// HITL — human-in-the-loop request approval. Rules with `action: hitl`
// pause the upstream call until an operator approves on the dashboard.
// Decisions arrive over a per-request channel; the gateway times out
// after Rule.HITLTimeout (default 60s). Notifier plugins (Slack,
// web-push, etc.) are fired when an approval becomes pending.

// HITLPending and HITLDecision moved to config/runtime — declared
// there so approver plugins can produce them without importing main.

// HITLRegistry is the pool of pending approvals + per-pending decision
// channel. Approver runtimes (config/plugins/approvers) call Add to
// publish a pending entry and select on the returned channel.
// Dashboard's PUT /api/hitl/decide calls Decide(id, allow) to resolve.
//
// Implements runtime.HITLPool via Add / Discard.
type HITLRegistry struct {
	mu      sync.Mutex
	pending map[string]*pendingEntry
	sink    *Sink // SSE fan-out for the dashboard
}

type pendingEntry struct {
	p        runtime.HITLPending
	decision chan runtime.HITLDecision
}

func newHITLRegistry(sink *Sink) *HITLRegistry {
	return &HITLRegistry{pending: map[string]*pendingEntry{}, sink: sink}
}

// Add publishes a pending entry and returns its assigned id + a
// decision channel. Caller selects on the channel and calls Discard
// when ctx fires before the channel.
func (r *HITLRegistry) Add(p runtime.HITLPending) (string, <-chan runtime.HITLDecision) {
	p.ID = randomString(16)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	if p.ExpiresAt.IsZero() {
		p.ExpiresAt = p.CreatedAt.Add(30 * time.Minute)
	}
	ch := make(chan runtime.HITLDecision, 1)
	r.mu.Lock()
	r.pending[p.ID] = &pendingEntry{p: p, decision: ch}
	r.mu.Unlock()
	if r.sink != nil {
		r.sink.Emit(Event{
			Mode: "hitl_pending", Host: p.Host, Method: p.Method,
			Path: p.Path, AgentIP: p.AgentIP, Reason: p.Reason, Action: "pending",
		})
	}
	return p.ID, ch
}

func (r *HITLRegistry) Discard(id string) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
}

func (r *HITLRegistry) List() []runtime.HITLPending {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]runtime.HITLPending, 0, len(r.pending))
	for _, e := range r.pending {
		out = append(out, e.p)
	}
	return out
}

// Decide fires the pending entry's channel. Returns false when the
// id is unknown (already discarded / never existed).
func (r *HITLRegistry) Decide(id string, d runtime.HITLDecision) bool {
	r.mu.Lock()
	e := r.pending[id]
	r.mu.Unlock()
	if e == nil {
		return false
	}
	select {
	case e.decision <- d:
		return true
	default:
		return false
	}
}
