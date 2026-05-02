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
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"golang.org/x/oauth2"
)

//go:embed all:www/dist
var dashboardFS embed.FS

//go:embed www/login.html
var loginHTML string

var loginTpl = template.Must(template.New("login").Parse(loginHTML))

type IntegrationRow struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	HasOAuth bool    `json:"has_oauth"`
	Owners   []Owner `json:"owners"`
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
	ts        GatewayConfig // for onboarding key minting
	publicURL string
	mu        sync.Mutex
	sessions  map[string]*oauthSession
	onboard   *onboardRegistry
}

func newWebMux(g *Gateway, caDir string, ts GatewayConfig, publicURL string) http.Handler {
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
	mux.HandleFunc("/api/oauth/start", w.apiOAuthStart)
	mux.HandleFunc("/api/oauth/exchange", w.apiOAuthExchange)
	mux.HandleFunc("/api/oauth/device-poll", w.apiOAuthDevicePoll)
	mux.HandleFunc("/api/oauth/revoke", w.apiOAuthRevoke)
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
// When dashboard_secret is empty the gate is a no-op — installs
// without an explicit secret keep their current open behavior.
func (w *webMux) dashboardSecretGate(next http.Handler) http.Handler {
	publicPaths := map[string]bool{
		"/api/onboard/start":   true,
		"/api/onboard/poll":    true,
		"/api/onboard/claim":   true,
		"/api/onboard/lookup":  true,
		"/api/onboard/approve": true,
		"/info":                true,
		"/ca.crt":              true,
		"/__login":             true,
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		secret := w.g.cfg.DashboardSecret
		if secret == "" || publicPaths[r.URL.Path] {
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
		"/api/onboard/start": true,
		"/api/onboard/poll":  true,
		"/api/onboard/claim": true, // device_code-gated; safe to be public
		"/info":              true,
		"/ca.crt":            true, // gateway's public CA cert, intentionally exposed
	}
	// In wireguard / proxy mode there is no tailnet identity to gate
	// against. Operators put the dashboard behind their own
	// authentication (Cloudflare Access, basic auth proxy, etc).
	skipGate := !strings.EqualFold(w.g.cfg.Gateway.Control, "tailscale") &&
		w.g.cfg.Gateway.Control != ""

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
	if profiles := w.g.cfg.Profiles; len(profiles) > 0 {
		return profiles[0].Name, profiles[0].Name
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

func (w *webMux) apiStatus(rw http.ResponseWriter, _ *http.Request) {
	out := []IntegrationRow{}
	for _, name := range allIntegrationKeys() {
		def, ok := defaultIntegrations[name]
		if !ok {
			continue
		}
		row := IntegrationRow{ID: name, Name: name}
		if def.OAuth != nil {
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
		out = append(out, row)
	}
	writeJSON(rw, out)
}

func (w *webMux) apiAgents(rw http.ResponseWriter, _ *http.Request) {
	var snap []*Agent
	if w.g.agents != nil {
		snap = w.g.agents.snapshot()
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
		var ids []string
		for _, id := range allIntegrationKeys() {
			if conn, _ := w.g.oauth.Status(id, profile); conn {
				ids = append(ids, id)
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
	known := false
	for _, p := range w.g.cfg.Profiles {
		if p.Name == profile {
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
	out := make([]string, 0, len(w.g.cfg.Profiles))
	for _, p := range w.g.cfg.Profiles {
		out = append(out, p.Name)
	}
	writeJSON(rw, out)
}

func (w *webMux) apiRules(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(rw, w.g.cfg.Rules)
	case "PUT":
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		var rules []Rule
		if err := json.Unmarshal(body, &rules); err != nil {
			http.Error(rw, "json: "+err.Error(), 400)
			return
		}
		w.g.cfg.Rules = rules
		rulesCopy := append([]Rule(nil), rules...)
		w.g.rules.Store(&rulesCopy)
		if err := writeConfigHCL(w.g.cfg, w.g.cfgPath); err != nil {
			http.Error(rw, "persist: "+err.Error(), 500)
			return
		}
		writeJSON(rw, map[string]any{"ok": true, "count": len(rules)})
	default:
		http.Error(rw, "GET or PUT", 405)
	}
}

// apiDeviceRules manages per-device rules. Device IP is read from
// ?ip= query param. Operations only touch rules with Device=ip; global
// rules (Device=="") are passed through untouched.
func (w *webMux) apiDeviceRules(rw http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(rw, "missing ip", 400)
		return
	}
	hcl := r.URL.Query().Get("format") == "hcl"
	switch r.Method {
	case "GET":
		deviceRules := []Rule{}
		for _, x := range w.g.cfg.Rules {
			if x.Device == ip {
				deviceRules = append(deviceRules, x)
			}
		}
		if hcl {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rw.Write(emitDeviceRulesHCL(w.g, ip, deviceRules))
			return
		}
		writeJSON(rw, deviceRules)
	case "PUT":
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		var newRules []Rule
		if hcl {
			var holder struct {
				Rules []Rule `hcl:"rule,block"`
			}
			if err := hclsimple.Decode("device.hcl", body, nil, &holder); err != nil {
				http.Error(rw, "hcl: "+err.Error(), 400)
				return
			}
			newRules = holder.Rules
		} else {
			if err := json.Unmarshal(body, &newRules); err != nil {
				http.Error(rw, "json: "+err.Error(), 400)
				return
			}
		}
		// Force Device=ip on every submitted rule (server-side trust:
		// don't let a device's editor accidentally edit other devices'
		// or global rules).
		for i := range newRules {
			newRules[i].Device = ip
		}
		var merged []Rule
		for _, x := range w.g.cfg.Rules {
			if x.Device != ip {
				merged = append(merged, x)
			}
		}
		merged = append(merged, newRules...)
		w.g.cfg.Rules = merged
		mergedCopy := append([]Rule(nil), merged...)
		w.g.rules.Store(&mergedCopy)
		if err := writeConfigHCL(w.g.cfg, w.g.cfgPath); err != nil {
			http.Error(rw, "persist: "+err.Error(), 500)
			return
		}
		writeJSON(rw, map[string]any{"ok": true, "count": len(newRules)})
	default:
		http.Error(rw, "GET or PUT", 405)
	}
}

// emitDeviceRulesHCL renders a per-device editing fragment: a
// commented summary of which profile the device sits in (read-only
// context for the operator) plus the editable `rule {}` blocks scoped
// to this device. Operators edit only the device-scoped rules; profile
// + global config lives in /api/config.
func emitDeviceRulesHCL(g *Gateway, ip string, deviceRules []Rule) []byte {
	profile := g.profileFor(ip)
	var b []byte
	b = append(b, []byte("# device: "+ip+"\n# profile: "+profile+"\n")...)
	b = append(b, []byte("# (this editor manages device-scoped rule overrides only —\n#  profile + global rules live in the gateway settings editor.)\n\n")...)
	if len(deviceRules) == 0 {
		b = append(b, []byte("# no device-scoped rules yet. Add `rule { ... }` blocks below.\n")...)
		return b
	}
	f := hclwrite.NewEmptyFile()
	for _, r := range deviceRules {
		f.Body().AppendNewline()
		writeRuleHCL(f.Body(), r)
	}
	b = append(b, f.Bytes()...)
	return b
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
		// validate by parsing into a fresh Config
		var probe Config
		if err := hclsimple.Decode("gateway.hcl", body, nil, &probe); err != nil {
			http.Error(rw, "hcl: "+err.Error(), 400)
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
	out, err := generateRuleHCL(r.Context(), w.g.oauth, body.Agent, owner, body.Prompt, body.CurrentYAML, body.Scope)
	if err != nil {
		http.Error(rw, "ai: "+err.Error(), 502)
		return
	}
	writeJSON(rw, map[string]string{"yaml": out})
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
	ok := w.g.hitl.Decide(body.ID, HITLDecision{Allow: body.Allow, By: owner})
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
	def, ok := defaultIntegrations[id]
	if !ok || def.OAuth == nil {
		http.Error(rw, "no oauth integration: "+id, 400)
		return
	}
	owner, ownerLabel := w.ownerForCaller(r)
	if owner == "" {
		http.Error(rw, "could not determine owner identity (tailscale whois failed)", 400)
		return
	}
	// Branch: device flow vs auth-code+PKCE.
	if def.OAuth.Flow == "device" {
		w.startDeviceFlow(rw, def.OAuth, owner, ownerLabel)
		return
	}

	verifier := randomString(64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomString(32)
	cfg := &oauth2.Config{
		ClientID:     resolveTemplate(def.OAuth.OAuth.ClientID),
		ClientSecret: resolveTemplate(def.OAuth.OAuth.ClientSecret),
		Scopes:       def.OAuth.OAuth.Scopes,
		RedirectURL:  def.OAuth.OAuth.RedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: def.OAuth.OAuth.AuthURL, TokenURL: def.OAuth.OAuth.TokenURL},
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
func (w *webMux) startDeviceFlow(rw http.ResponseWriter, it *OAuthIntegration, owner, ownerLabel string) {
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
		id:       it.ID,
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
	log.Printf("DEBUG device-poll %s status=%d body=%s", sess.id, resp.StatusCode, truncate(string(body), 400))
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
	if profile == "" && len(w.g.cfg.Profiles) > 0 {
		profile = w.g.cfg.Profiles[0].Name
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
	w.onboard.mu.Unlock()

	// Mint key in background so the approve click returns fast.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		key, loginServer, peerIP, err := newOnboarder(w.ts).MintKey(ctx)
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

type HITLDecision struct {
	Allow  bool
	Reason string
	By     string // user who approved
}

type HITLPending struct {
	ID         string    `json:"id"`
	AgentIP    string    `json:"agent_ip"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UA         string    `json:"ua,omitempty"`
	BodySample string    `json:"body_sample,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Approvers  []string  `json:"approvers,omitempty"` // names from rule.Approve
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	decision   chan HITLDecision
}

type HITLNotifier interface {
	Notify(p *HITLPending)
}

type HITLRegistry struct {
	mu        sync.Mutex
	pending   map[string]*HITLPending
	notifiers []HITLNotifier
}

func newHITLRegistry() *HITLRegistry {
	return &HITLRegistry{pending: map[string]*HITLPending{}}
}

func (r *HITLRegistry) Register(n HITLNotifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifiers = append(r.notifiers, n)
}

// Wait registers a pending approval and blocks until decision OR ctx
// timeout. Notifier plugins are fired (best-effort) before the wait.
func (r *HITLRegistry) Wait(ctx context.Context, p *HITLPending, timeout time.Duration) HITLDecision {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	p.ID = randomString(16)
	p.CreatedAt = time.Now()
	p.ExpiresAt = p.CreatedAt.Add(timeout)
	p.decision = make(chan HITLDecision, 1)

	r.mu.Lock()
	r.pending[p.ID] = p
	notifiers := append([]HITLNotifier(nil), r.notifiers...)
	r.mu.Unlock()

	for _, n := range notifiers {
		go func(n HITLNotifier) { n.Notify(p) }(n)
	}

	defer func() {
		r.mu.Lock()
		delete(r.pending, p.ID)
		r.mu.Unlock()
	}()

	select {
	case d := <-p.decision:
		return d
	case <-time.After(timeout):
		return HITLDecision{Allow: false, Reason: "approval timed out"}
	case <-ctx.Done():
		return HITLDecision{Allow: false, Reason: "request cancelled"}
	}
}

func (r *HITLRegistry) List() []*HITLPending {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*HITLPending, 0, len(r.pending))
	for _, p := range r.pending {
		out = append(out, p)
	}
	return out
}

func (r *HITLRegistry) Decide(id string, d HITLDecision) bool {
	r.mu.Lock()
	p := r.pending[id]
	r.mu.Unlock()
	if p == nil {
		return false
	}
	select {
	case p.decision <- d:
		return true
	default:
		return false
	}
}

// hitlSinkNotifier fan-outs pending approvals onto the gateway's main
// event sink so the dashboard SSE stream picks them up alongside
// regular request events. Mode=hitl_pending.
type hitlSinkNotifier struct{ sink *Sink }

func (n *hitlSinkNotifier) Notify(p *HITLPending) {
	n.sink.Emit(Event{
		Mode:    "hitl_pending",
		Host:    p.Host,
		Method:  p.Method,
		Path:    p.Path,
		AgentIP: p.AgentIP,
		Reason:  p.Reason,
		Action:  "pending",
	})
}
