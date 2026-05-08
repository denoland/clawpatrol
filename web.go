package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

//go:embed all:www/dist
var dashboardFS embed.FS

//go:embed www/login.html
var loginHTML string

var loginTpl = template.Must(template.New("login").Parse(loginHTML))

type webMux struct {
	g         *Gateway
	caDir     string
	ts        Tailscale // for onboarding key minting
	publicURL string
	mu        sync.Mutex
	sessions  map[string]*oauthSession
	onboard   *onboardRegistry

	// stateCache: per-caller TTL'd memo for /api/state. RWMutex
	// because reads vastly outnumber writes — every dashboard tab
	// polls every 5s, but the cached entry only refreshes once per
	// stateCacheTTL (1s). 99% of polls are RLock-only.
	stateCacheMu sync.RWMutex
	stateCache   map[string]stateCacheEntry
}

func newWebMux(g *Gateway, caDir string, ts Tailscale, publicURL string) http.Handler {
	w := &webMux{g: g, caDir: caDir, ts: ts, publicURL: publicURL, sessions: map[string]*oauthSession{}, onboard: g.onboard}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", w.serveInfo)
	mux.HandleFunc("/ca.crt", w.serveCA)
	// /api/whoami + /api/agents are gone — superseded by /api/state.
	// /api/status stays because DevicePage scopes it with ?profile=.
	mux.HandleFunc("/api/status", w.apiStatus)
	// /api/state is the dashboard's single-call refresh endpoint —
	// bundles whoami+status+agents in one round-trip and returns 304
	// when the JSON hash matches If-None-Match. Replaces the three
	// parallel per-3s fetches App.refresh used to fire.
	mux.HandleFunc("/api/state", w.apiState)
	mux.HandleFunc("/api/agents/delete", w.apiAgentDelete)
	mux.HandleFunc("/api/agents/profile", w.apiAgentProfile)
	mux.HandleFunc("/api/profiles", w.apiProfiles)
	mux.HandleFunc("/api/rules", w.apiRules)
	mux.HandleFunc("/api/rules/ai", w.apiRulesAI)
	mux.HandleFunc("/api/config", w.apiConfig)
	mux.HandleFunc("/api/hitl/pending", w.apiHITLPending)
	mux.HandleFunc("/api/hitl/decide", w.apiHITLDecide)
	w.mountCredentialWebhooks(mux)
	mux.HandleFunc("/api/oauth/start", w.apiOAuthStart)
	mux.HandleFunc("/api/oauth/exchange", w.apiOAuthExchange)
	mux.HandleFunc("/api/oauth/device-poll", w.apiOAuthDevicePoll)
	mux.HandleFunc("/api/oauth/revoke", w.apiOAuthRevoke)
	mux.HandleFunc("/api/credentials/set", w.apiCredentialsSet)
	mux.HandleFunc("/api/credentials/clear", w.apiCredentialsClear)
	mux.HandleFunc("/api/events", w.apiEventsSSE)
	mux.HandleFunc("/api/actions/", w.apiActionByID)
	mux.HandleFunc("/api/analytics", w.apiAnalytics)
	mux.HandleFunc("/api/onboard/start", w.apiOnboardStart)
	mux.HandleFunc("/api/onboard/poll", w.apiOnboardPoll)
	mux.HandleFunc("/api/onboard/approve", w.apiOnboardApprove)
	mux.HandleFunc("/api/onboard/lookup", w.apiOnboardLookup)
	mux.HandleFunc("/api/onboard/claim", w.apiOnboardClaim)
	mux.HandleFunc("/api/env-pushdown", w.apiEnvPushdown)
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
// credentialWebhookPrefix is the path prefix every plugin webhook
// route mounts under. Public — credential plugins authenticate
// callbacks via their own signature header (Slack signing secret,
// etc.) so the dashboard secret gate skips the prefix.
const credentialWebhookPrefix = "/api/cred/"

func (w *webMux) dashboardSecretGate(next http.Handler) http.Handler {
	publicPaths := map[string]bool{
		"/api/onboard/start":   true,
		"/api/onboard/poll":    true,
		"/api/onboard/claim":   true,
		"/api/onboard/lookup":  true,
		"/api/onboard/approve": true,
		// /api/env-pushdown is NOT public — it's gated by the
		// per-peer bearer minted at onboard time. The handler
		// validates `Authorization: Bearer <token>` against
		// peer_api_tokens; dashboardSecretGate doesn't need to
		// see it.
		"/api/env-pushdown": true,
		"/info":             true,
		"/ca.crt":           true,
		"/__login":          true,
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
		if publicPaths[r.URL.Path] || strings.HasPrefix(r.URL.Path, credentialWebhookPrefix) {
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

// mountCredentialWebhooks walks every credential whose body
// implements runtime.WebhookProvider and mounts each declared route
// under /api/cred/<credName>/<route.Path>. Future plugins (Discord,
// Telegram, generic webhook) plug in by implementing WebhookRoutes()
// — main needs no plugin-specific path table.
func (w *webMux) mountCredentialWebhooks(mux *http.ServeMux) {
	policy := w.g.Policy()
	if policy == nil {
		return
	}
	for name, ent := range policy.Credentials {
		provider, ok := ent.Body.(runtime.WebhookProvider)
		if !ok {
			continue
		}
		credName := name
		for _, route := range provider.WebhookRoutes() {
			path := credentialWebhookPrefix + credName + route.Path
			handler := route.Handler
			mux.HandleFunc(path, func(rw http.ResponseWriter, r *http.Request) {
				ctx := runtime.WebhookCtx{
					CredentialName: credName,
					Secrets:        w.g.secrets,
					HITL:           w.g.hitl,
					Policy:         w.g.Policy(),
					Profiles:       orderedProfileNames(w.g.cfg.Policy),
				}
				handler(ctx, rw, r)
			})
		}
	}
}

// apiEnvPushdown returns the env-var push-down list assembled from
// the gateway's currently-loaded policy, scoped to the calling
// peer's profile. Clients (`clawpatrol env`, `clawpatrol run`)
// fetch this instead of iterating their own compiled-in plugin
// set, so the binary on the client doesn't have to track which
// endpoint plugins the operator has enabled on the gateway.
//
// Auth: requires `Authorization: Bearer <token>` where <token>
// matches a row in peer_api_tokens. The token was minted for the
// caller at onboard-approve time and persisted next to ca.crt by
// `clawpatrol join`. Only the (name, value, description,
// plugin_type) bytes for plugins reachable from the peer's
// profile are returned; CA-bundle vars stay client-side because
// they reference a path on the *client's* disk.
func (w *webMux) apiEnvPushdown(rw http.ResponseWriter, r *http.Request) {
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	peerIP := peerIPForAPIToken(w.g.db, token)
	if peerIP == "" {
		http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
		return
	}
	profileName := w.g.profileFor(peerIP)
	policy := w.g.Policy()
	if policy == nil {
		writeJSON(rw, map[string]any{"vars": []any{}})
		return
	}
	prof, ok := policy.Profiles[profileName]
	if !ok || prof == nil {
		writeJSON(rw, map[string]any{"vars": []any{}})
		return
	}

	out := []map[string]string{}
	seen := map[string]bool{}
	add := func(name, value, description, pluginType string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, map[string]string{
			"name":        name,
			"value":       value,
			"description": description,
			"plugin_type": pluginType,
		})
	}
	credSeen := map[string]bool{}
	// Endpoints in this profile, plus the credentials they bind.
	// Credentials are emitted first (so credential-shaped
	// placeholders win on duplicate names), endpoints second.
	for _, ep := range prof.Endpoints {
		for _, cc := range ep.Credentials {
			if cc == nil || cc.Credential == nil || credSeen[cc.Credential.Symbol.Name] {
				continue
			}
			credSeen[cc.Credential.Symbol.Name] = true
			provider, ok := cc.Credential.Body.(config.EnvPushdownProvider)
			if !ok {
				continue
			}
			for _, ev := range provider.EnvVars() {
				add(ev.Name, ev.Value, ev.Description, cc.Credential.Plugin.Type)
			}
		}
	}
	for _, ep := range prof.Endpoints {
		provider, ok := ep.Body.(config.EnvPushdownProvider)
		if !ok {
			continue
		}
		for _, ev := range provider.EnvVars() {
			add(ev.Name, ev.Value, ev.Description, ep.Plugin.Type)
		}
	}
	writeJSON(rw, map[string]any{"vars": out})
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
	if def := defaultProfileName(w.g.cfg.Policy); def != "" {
		return def, def
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

// whoamiData backs the whoami slice of /api/state. No HTTP handler —
// the route was removed once App.tsx switched to the bundled
// /api/state response.
func (w *webMux) whoamiData(r *http.Request) map[string]string {
	user, device, host := w.callerIdentity(r)
	pu := w.g.cfg.PublicURL
	if pu == "" {
		pu = w.publicURL
	}
	return map[string]string{
		"user":       user,
		"device":     device,
		"host":       host,
		"public_url": pu,
	}
}

// apiState is the dashboard's combined refresh endpoint. Bundles
// whoami + status (integrations) + agents into one response with an
// ETag — when the JSON hash matches If-None-Match the gateway returns
// 304 with no body. Server-side caches the last (tag, body) under a
// short TTL so concurrent dashboards on the same tag answer 304
// without re-marshaling+hashing; only the first request per change-
// window pays the full cost. Whoami varies per-caller so the cache
// is keyed by (caller-user, profile).
//
// Cache TTL is conservatively short (1s) so changes propagate to
// idle dashboards within their 5s poll window without us needing a
// real invalidation hook off every credential mutation.
func (w *webMux) apiState(rw http.ResponseWriter, r *http.Request) {
	user, _, _ := w.callerIdentity(r)
	cacheKey := user + "|" + r.URL.Query().Get("profile")
	now := time.Now()

	w.stateCacheMu.RLock()
	if c, ok := w.stateCache[cacheKey]; ok && now.Sub(c.At) < stateCacheTTL {
		body, tag := c.Body, c.Tag
		w.stateCacheMu.RUnlock()
		serveState(rw, r, body, tag)
		return
	}
	w.stateCacheMu.RUnlock()

	state := map[string]any{
		"whoami":       w.whoamiData(r),
		"integrations": w.statusList(r),
		"agents":       w.agentsList(),
	}
	body, err := json.Marshal(state)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	sum := sha256.Sum256(body)
	tag := `"` + hex.EncodeToString(sum[:8]) + `"`

	w.stateCacheMu.Lock()
	if w.stateCache == nil {
		w.stateCache = map[string]stateCacheEntry{}
	}
	w.stateCache[cacheKey] = stateCacheEntry{Body: body, Tag: tag, At: now}
	w.stateCacheMu.Unlock()

	serveState(rw, r, body, tag)
}

const stateCacheTTL = 1 * time.Second

type stateCacheEntry struct {
	Body []byte
	Tag  string
	At   time.Time
}

func serveState(rw http.ResponseWriter, r *http.Request, body []byte, tag string) {
	if r.Header.Get("If-None-Match") == tag {
		rw.Header().Set("ETag", tag)
		rw.WriteHeader(http.StatusNotModified)
		return
	}
	rw.Header().Set("ETag", tag)
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Write(body)
}

// apiStatus returns the credentials list for the dashboard. Filters
// by profile when ?profile=NAME is set — only credentials referenced
// by an endpoint in that profile come back. Without the param, every
// declared credential ships (root view).

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
	// Backlog ships as a single `event: backlog` SSE message carrying
	// the whole array. Client renders that batch in one commit (no
	// per-event rAF flood), then switches to per-event live streaming.
	// Default event channel = live only.
	if len(backlog) > 0 {
		filtered := backlog
		if wantIP != "" {
			filtered = filtered[:0]
			for _, ev := range backlog {
				if ev.AgentIP == wantIP {
					filtered = append(filtered, ev)
				}
			}
		}
		if len(filtered) > 0 {
			b, err := json.Marshal(filtered)
			if err == nil {
				fmt.Fprintf(rw, "event: backlog\ndata: %s\n\n", b)
			}
		}
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
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			if wantIP != "" && pkt.ev.AgentIP != wantIP {
				continue
			}
			fmt.Fprintf(rw, "data: %s\n\n", pkt.raw)
			flusher.Flush()
		}
	}
}

func (w *webMux) apiActionByID(
	rw http.ResponseWriter, r *http.Request,
) {
	// Path: /api/actions/<uuid>
	actionID := strings.TrimPrefix(r.URL.Path, "/api/actions/")
	if actionID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	var (
		e           Event
		tsNs        int64
		mode        sql.NullString
		agentIP     sql.NullString
		method      sql.NullString
		path        sql.NullString
		status      sql.NullInt64
		in, ot      sql.NullInt64
		ms          sql.NullInt64
		action      sql.NullString
		reason      sql.NullString
		reqSha      sql.NullString
		respSha     sql.NullString
		reqBody     sql.NullString
		respBody    sql.NullString
		reqHeaders  sql.NullString
		respHeaders sql.NullString
	)
	err := w.g.db.QueryRow(`
		SELECT ts_ns, mode, agent_ip, host, method, path,
		       status, bytes_in, bytes_out, ms, action,
		       reason, req_sha, resp_sha,
		       req_body, resp_body,
		       req_headers, resp_headers
		FROM actions WHERE action_id = ?`, actionID,
	).Scan(
		&tsNs, &mode, &agentIP, &e.Host,
		&method, &path, &status, &in, &ot, &ms,
		&action, &reason, &reqSha, &respSha,
		&reqBody, &respBody,
		&reqHeaders, &respHeaders,
	)
	if err == sql.ErrNoRows {
		http.Error(rw, "not found", 404)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	e.ID = actionID
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
	e.ReqBody = reqBody.String
	e.RespBody = respBody.String
	unmarshalHeaders(reqHeaders.String, &e.ReqHeaders)
	unmarshalHeaders(respHeaders.String, &e.RespHeaders)
	writeJSON(rw, e)
}

// apiAnalytics returns a randomly-sampled set of events for the
// analytics charts. Query params:
//
//	range  — duration string (1m, 5m, 15m, 30m, 1h, 6h, 24h)
//	agent  — optional agent IP filter
//	limit  — max rows (default 5000)
func (w *webMux) apiAnalytics(
	rw http.ResponseWriter, r *http.Request,
) {
	q := r.URL.Query()
	rangeStr := q.Get("range")
	if rangeStr == "" {
		rangeStr = "1h"
	}
	dur, err := time.ParseDuration(
		strings.TrimSuffix(rangeStr, "m") + "m0s",
	)
	// Parse shorthand: 1m, 5m, 30m, 1h, 6h, 24h
	switch rangeStr {
	case "1m":
		dur = time.Minute
	case "5m":
		dur = 5 * time.Minute
	case "15m":
		dur = 15 * time.Minute
	case "30m":
		dur = 30 * time.Minute
	case "1h":
		dur = time.Hour
	case "6h":
		dur = 6 * time.Hour
	case "24h":
		dur = 24 * time.Hour
	default:
		if err != nil {
			dur = time.Hour
		}
	}
	cutoff := time.Now().Add(-dur).UnixNano()
	limit := 5000
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 10000 {
				n = 10000
			}
			limit = n
		}
	}
	agent := q.Get("agent")

	where := "ts_ns >= ?"
	whereArgs := []any{cutoff}
	if agent != "" {
		where += " AND agent_ip = ?"
		whereArgs = append(whereArgs, agent)
	}

	// Sort by the random suffix of action_id (UUIDv7, so the last
	// chars are uniform random) instead of RANDOM(). Same range +
	// agent → same sample, so a polling dashboard doesn't reshuffle
	// the scatter every 10 s.
	query := `
		SELECT action_id, ts_ns, mode, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason
		FROM actions
		WHERE ` + where + `
		ORDER BY COALESCE(substr(action_id, -8), CAST(ts_ns AS TEXT))
		LIMIT ?`
	args := append(append([]any{}, whereArgs...), limit)
	rows, err := w.g.db.Query(query, args...)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := make([]Event, 0, 256)
	for rows.Next() {
		var (
			e        Event
			actionID sql.NullString
			tsNs     int64
			mode     sql.NullString
			agentIP  sql.NullString
			method   sql.NullString
			path     sql.NullString
			status   sql.NullInt64
			in, ot   sql.NullInt64
			ms       sql.NullInt64
			action   sql.NullString
			reason   sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason,
		); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		e.ID = actionID.String
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
		out = append(out, e)
	}

	// Real (non-sampled) totals so the top stats reflect the actual
	// request volume, not the chart's 5000-row sample. Filtered by
	// the same range + agent as the events query above.
	var totalCount int64
	var errorCount sql.NullInt64
	_ = w.g.db.QueryRow(
		`SELECT COUNT(*),
		        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END)
		 FROM actions WHERE `+where, whereArgs...,
	).Scan(&totalCount, &errorCount)

	// Real per-device / per-host counts so the bar lists aren't
	// capped at the sample size either. Same filter; bar charts only
	// render the top ~10 so 50 is a generous cap.
	byDevice := groupCount(w.g.db,
		`SELECT agent_ip, COUNT(*) FROM actions
		 WHERE `+where+` AND agent_ip IS NOT NULL AND agent_ip != ''
		 GROUP BY agent_ip ORDER BY 2 DESC LIMIT 50`,
		whereArgs)
	byHost := groupCount(w.g.db,
		`SELECT host, COUNT(*) FROM actions
		 WHERE `+where+` AND host IS NOT NULL AND host != ''
		 GROUP BY host ORDER BY 2 DESC LIMIT 50`,
		whereArgs)

	writeJSON(rw, map[string]any{
		"events":      out,
		"total":       len(out),
		"total_count": totalCount,
		"error_count": errorCount.Int64,
		"by_device":   byDevice,
		"by_host":     byHost,
	})
}

func groupCount(db *sql.DB, q string, args []any) []map[string]any {
	out := []map[string]any{}
	rows, err := db.Query(q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k sql.NullString
		var c int64
		if err := rows.Scan(&k, &c); err != nil || !k.Valid {
			continue
		}
		out = append(out, map[string]any{
			"key": k.String, "count": c,
		})
	}
	return out
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(v)
}

// apiOnboardStart begins device-flow onboarding. Public (no auth)
// since this IS how a brand-new client first contacts the gateway.
// The returned user_code must still be approved by an existing tailnet
// member on the dashboard.
func allIntegrationKeys() []string { return displayOrder }

// Event sink + sampling helpers (fed by g.handle/mitm/splice; consumed
// by the dashboard SSE stream and the on-disk event log).

type Event struct {
	Ts          time.Time         `json:"ts"`
	ID          string            `json:"id,omitempty"`    // UUIDv7; correlates start/end/frame + DB key
	Phase       string            `json:"phase,omitempty"` // "" (legacy/end), "start", "end", "frame"
	Mode        string            `json:"mode"`
	Agent       string            `json:"agent,omitempty"`
	AgentIP     string            `json:"agent_ip,omitempty"`
	Host        string            `json:"host"`
	Method      string            `json:"method,omitempty"`
	Path        string            `json:"path,omitempty"`
	Status      int               `json:"status,omitempty"`
	In          int64             `json:"in,omitempty"`
	Out         int64             `json:"out,omitempty"`
	Ms          int64             `json:"ms"`
	Action      string            `json:"action,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	ReqSha      string            `json:"req_sha,omitempty"`
	ReqBody     string            `json:"req_body,omitempty"`
	RespSha     string            `json:"resp_sha,omitempty"`
	RespBody    string            `json:"resp_body,omitempty"`
	ReqHeaders  map[string]string `json:"req_headers,omitempty"`
	RespHeaders map[string]string `json:"resp_headers,omitempty"`
	// Frame is set for Phase="frame" only — a single WS frame's text
	// payload (truncated at sampleCap). Direction is "c→s" or "s→c"
	// to disambiguate masked client frames from unmasked server frames.
	Frame     string `json:"frame,omitempty"`
	Direction string `json:"direction,omitempty"`
}

// eventPacket carries an event plus its marshaled JSON bytes. drain()
// marshals once and ships the same bytes to every subscriber so a
// busy gateway doesn't pay N × json.Marshal per event when N
// dashboards are connected.
type eventPacket struct {
	ev  Event
	raw []byte
}

type Sink struct {
	ch    chan Event
	db    *sql.DB
	drops atomic.Uint64
	mu    sync.Mutex
	subs  []chan eventPacket
	// Recent ring backlog. recent is sized once at construction; we
	// write at recentNext (modulo cap) and rotate. Old behavior used
	// `append + slice` which reallocated on every overflow, churning
	// GC at ~10 alloc/sec on a busy gateway. Lazy fill: until we wrap,
	// recentLen tracks valid entries.
	recent     []Event
	recentNext int
	recentLen  int
	recentCap  int
}

func NewSink(db *sql.DB, buf int) (*Sink, error) {
	s := &Sink{ch: make(chan Event, buf), db: db, recentCap: 500}
	s.recent = make([]Event, s.recentCap)
	if db != nil {
		if seed, err := readTailEvents(db, s.recentCap); err == nil && len(seed) > 0 {
			// Seed fills oldest→newest; place at indices 0..len(seed)-1
			// and set recentNext to the next slot, recentLen to length.
			n := len(seed)
			if n > s.recentCap {
				seed = seed[n-s.recentCap:]
				n = s.recentCap
			}
			copy(s.recent, seed)
			s.recentLen = n
			s.recentNext = n % s.recentCap
		}
	}
	go s.drain()
	return s, nil
}

func readTailEvents(db *sql.DB, n int) ([]Event, error) {
	rows, err := db.Query(`
		SELECT action_id, ts_ns, mode, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason, req_sha, resp_sha
		FROM actions ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Event, 0, n)
	for rows.Next() {
		var (
			e        Event
			actionID sql.NullString
			tsNs     int64
			mode     sql.NullString
			agentIP  sql.NullString
			method   sql.NullString
			path     sql.NullString
			status   sql.NullInt64
			in, ot   sql.NullInt64
			ms       sql.NullInt64
			action   sql.NullString
			reason   sql.NullString
			reqSha   sql.NullString
			respSha  sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason, &reqSha, &respSha,
		); err != nil {
			return nil, err
		}
		e.ID = actionID.String
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
		// Persist only terminal events. start/frame are transient
		// signals for live SSE — duplicating them in `actions` would
		// double-count requests in the request-history view and bloat
		// the table for long-poll / WS sessions.
		persist := e.Phase == "" || e.Phase == "end"
		if persist && e.ID == "" {
			// Some connection-oriented endpoint runtimes emit a single terminal
			// event instead of the HTTP start/end pair. Give those events a
			// stable action_id before DB insert + SSE fan-out so every persisted
			// live-request row can navigate to /api/actions/<id>.
			e.ID = newReqID()
		}
		if s.db != nil && persist {
			var rqhJSON, rshJSON []byte
			if len(e.ReqHeaders) > 0 {
				rqhJSON, _ = json.Marshal(e.ReqHeaders)
			}
			if len(e.RespHeaders) > 0 {
				rshJSON, _ = json.Marshal(e.RespHeaders)
			}
			s.db.Exec(`
				INSERT INTO actions
				 (action_id, ts_ns, mode, agent_ip, host,
				  method, path, status, bytes_in, bytes_out,
				  ms, action, reason, req_sha, resp_sha,
				  req_body, resp_body,
				  req_headers, resp_headers)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			`, e.ID, e.Ts.UnixNano(), e.Mode, e.AgentIP,
				e.Host, e.Method, e.Path, e.Status,
				e.In, e.Out, e.Ms, e.Action, e.Reason,
				e.ReqSha, e.RespSha,
				e.ReqBody, e.RespBody,
				string(rqhJSON), string(rshJSON))
		}

		// Marshal once per event regardless of subscriber count. Old
		// path marshaled inside each subscriber's SSE handler — N
		// dashboards = N json.Marshal calls per event. Now it's 1.
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		pkt := eventPacket{ev: e, raw: raw}

		s.mu.Lock()
		// Recent ring updated under lock since RecentAndSubscribe
		// snapshots it. Circular write: O(1) regardless of cap.
		// Strip bodies from the backlog copy — SSE consumers only
		// need metadata; the detail page fetches full data via
		// /api/actions/<id>.
		if persist {
			lite := e
			lite.ReqBody = ""
			lite.RespBody = ""
			lite.ReqHeaders = nil
			lite.RespHeaders = nil
			s.recent[s.recentNext] = lite
			s.recentNext = (s.recentNext + 1) % s.recentCap
			if s.recentLen < s.recentCap {
				s.recentLen++
			}
		}
		// Copy subs out of the lock, fan-out without holding mu so
		// a slow channel doesn't serialize the gateway. Cheap copy
		// (slice of channel pointers, len ~= dashboards open).
		subs := append([]chan eventPacket(nil), s.subs...)
		s.mu.Unlock()

		for _, sub := range subs {
			select {
			case sub <- pkt:
			default:
				// slow consumer; drop
				s.drops.Add(1)
			}
		}
	}
}

// recentSnapshot copies the ring into a flat oldest→newest slice.
// Caller must hold s.mu (or call from RecentAndSubscribe which does).
func (s *Sink) recentSnapshot() []Event {
	if s.recentLen == 0 {
		return nil
	}
	out := make([]Event, s.recentLen)
	if s.recentLen < s.recentCap {
		copy(out, s.recent[:s.recentLen])
		return out
	}
	// Wrapped: oldest entry sits at recentNext, walk forward modulo cap.
	for i := 0; i < s.recentCap; i++ {
		out[i] = s.recent[(s.recentNext+i)%s.recentCap]
	}
	return out
}

// RecentAndSubscribe atomically snapshots the backlog and registers a
// subscriber under the same lock so no event is missed or duplicated
// between the two. Channel ships eventPackets — drain marshaled the
// JSON once and shares those bytes across every subscriber.
func (s *Sink) RecentAndSubscribe() ([]Event, <-chan eventPacket, func()) {
	if s == nil {
		ch := make(chan eventPacket)
		close(ch)
		return nil, ch, func() {}
	}
	ch := make(chan eventPacket, 64)
	s.mu.Lock()
	snap := s.recentSnapshot()
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

func (s *Sink) Subscribe() (<-chan eventPacket, func()) {
	_, ch, cancel := s.RecentAndSubscribe()
	return ch, cancel
}

type sampler struct {
	hash hash.Hash
	cap  int
	buf  bytes.Buffer
	n    int64
}

func unmarshalHeaders(s string, dst *map[string]string) {
	if s != "" {
		_ = json.Unmarshal([]byte(s), dst)
	}
}

var sensitiveHeader = regexp.MustCompile(
	`(?i)auth|token|secret|key|password|cookie`,
)

func flatHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if sensitiveHeader.MatchString(k) {
			out[k] = "***"
		} else {
			out[k] = strings.Join(v, ", ")
		}
	}
	return out
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
