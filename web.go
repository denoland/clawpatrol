package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/runtime"
)

//go:embed all:www/dist
var dashboardFS embed.FS

//go:embed www/login.html
var loginHTML string

var loginTpl = template.Must(template.New("login").Parse(loginHTML))

var errConfigRevisionConflict = errors.New("config revision conflict")

type webMux struct {
	g         *Gateway
	caDir     string
	ts        JoinConfig // for onboarding key minting
	publicURL string
	mu        sync.Mutex
	sessions  map[string]*oauthSession
	onboard   *onboardRegistry
	previews  map[string]configPreviewToken
	routeAuth map[string]authRequirement

	// stateCache: per-caller TTL'd memo for /api/state. RWMutex
	// because reads vastly outnumber writes — every dashboard tab
	// polls every 5s, but the cached entry only refreshes once per
	// stateCacheTTL (1s). 99% of polls are RLock-only.
	stateCacheMu sync.RWMutex
	stateCache   map[string]stateCacheEntry
}

type configPreviewToken struct {
	revision    string
	contentHash string
}

type authRequirement int

const (
	// authDashboard routes require the configured dashboard secret before
	// they can reach the handler. In Tailscale control mode, the existing
	// tailnet gate still runs after dashboard auth.
	authDashboard authRequirement = iota
	// authPublic routes are intentionally reachable before any dashboard
	// or tailnet identity exists.
	authPublic
	// authTailnetOperator routes skip dashboard-secret auth but are still
	// protected by tailnet identity when Tailscale control mode is active.
	authTailnetOperator
	// authDashboardOrTailnetOperator accepts dashboard auth everywhere and
	// may defer to tailnet identity in Tailscale control mode. In WireGuard
	// / proxy mode there is no tailnet identity, so dashboard auth remains
	// mandatory.
	authDashboardOrTailnetOperator
	// authSelfAuthenticating routes carry their own request-level proof
	// (for example a bearer token or webhook signature), so they do not
	// require the dashboard secret. Existing tailnet-gate behavior is kept.
	authSelfAuthenticating
)

type webRoute struct {
	Method  string
	Path    string
	Auth    authRequirement
	Handler http.HandlerFunc
}

type principalKind string

const (
	principalDashboardSecret principalKind = "dashboard_secret"
	principalTailnet         principalKind = "tailnet"
)

type principal struct {
	Kind   principalKind
	Owner  string
	User   string
	Device string
	Host   string
}

type principalContextKey struct{}

func contextWithPrincipal(ctx context.Context, p principal) context.Context {
	if p.Owner == "" {
		p.Owner = p.User
	}
	return context.WithValue(ctx, principalContextKey{}, p)
}

func principalFromContext(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(principal)
	if !ok || p.Owner == "" {
		return principal{}, false
	}
	return p, true
}

func (w *webMux) dashboardSecretPrincipal() principal {
	owner := w.g.cfg.AdminEmail
	if owner == "" {
		owner = "dashboard"
	}
	return principal{Kind: principalDashboardSecret, Owner: owner}
}

func routeAuthIndex(routes []webRoute) map[string]authRequirement {
	out := make(map[string]authRequirement, len(routes))
	for _, route := range routes {
		out[route.Path] = route.Auth
	}
	return out
}

func (w *webMux) authRequirementForPath(path string) authRequirement {
	if strings.HasPrefix(path, credentialWebhookPrefix) {
		return authSelfAuthenticating
	}
	if w.routeAuth != nil {
		if req, ok := w.routeAuth[path]; ok {
			return req
		}
	}
	return authDashboard
}

func (w *webMux) skipsDashboardSecret(path string) bool {
	switch w.authRequirementForPath(path) {
	case authPublic, authTailnetOperator, authSelfAuthenticating:
		return true
	default:
		return false
	}
}

func isTailscaleControlMode(control string) bool {
	return control == "" || strings.EqualFold(control, "tailscale")
}

func (w *webMux) mayUseTailnetInsteadOfDashboard(path string) bool {
	return w.authRequirementForPath(path) == authDashboardOrTailnetOperator &&
		isTailscaleControlMode(w.g.cfg.Control)
}

func (w *webMux) skipsTailnetGate(path string) bool {
	return w.authRequirementForPath(path) == authPublic
}

func newWebMux(g *Gateway, caDir string, ts JoinConfig, publicURL string) http.Handler {
	w := &webMux{g: g, caDir: caDir, ts: ts, publicURL: publicURL, sessions: map[string]*oauthSession{}, onboard: g.onboard, previews: map[string]configPreviewToken{}}
	return w.handler()
}

func (w *webMux) handler() http.Handler {
	mux := http.NewServeMux()
	routes := w.routes()
	w.routeAuth = routeAuthIndex(routes)
	for _, route := range routes {
		if route.Method == "" {
			panic("web route missing method: " + route.Path)
		}
		mux.HandleFunc(route.Path, route.Handler)
	}
	w.mountCredentialWebhooks(mux)
	mux.Handle("/", w.staticHandler())
	return w.dashboardSecretGate(w.tailnetGate(mux))
}

func (w *webMux) routes() []webRoute {
	return []webRoute{
		{Method: http.MethodGet, Path: "/info", Auth: authPublic, Handler: w.serveInfo},
		{Method: http.MethodGet, Path: "/ca.crt", Auth: authPublic, Handler: w.serveCA},
		// /api/whoami + /api/agents are gone — superseded by /api/state.
		// /api/status stays because DevicePage scopes it with ?profile=.
		{Method: http.MethodGet, Path: "/api/status", Auth: authDashboard, Handler: w.apiStatus},
		// /api/state is the dashboard's single-call refresh endpoint —
		// bundles whoami+status+agents in one round-trip and returns 304
		// when the JSON hash matches If-None-Match. Replaces the three
		// parallel per-3s fetches App.refresh used to fire.
		{Method: http.MethodGet, Path: "/api/state", Auth: authDashboard, Handler: w.apiState},
		{Method: http.MethodPost, Path: "/api/agents/delete", Auth: authDashboard, Handler: w.apiAgentDelete},
		{Method: http.MethodPost, Path: "/api/agents/profile", Auth: authDashboard, Handler: w.apiAgentProfile},
		{Method: http.MethodGet, Path: "/api/profiles", Auth: authDashboard, Handler: w.apiProfiles},
		{Method: http.MethodGet, Path: "/api/rules", Auth: authDashboard, Handler: w.apiRules},
		{Method: http.MethodPost, Path: "/api/rules/ai", Auth: authDashboard, Handler: w.apiRulesAI},
		{Method: http.MethodGet, Path: "/api/config", Auth: authDashboard, Handler: w.apiConfig},
		{Method: http.MethodPost, Path: "/api/config/preview", Auth: authDashboard, Handler: w.apiConfigPreview},
		{Method: http.MethodPost, Path: "/api/config/save", Auth: authDashboard, Handler: w.apiConfigSave},
		{Method: http.MethodGet, Path: "/api/hitl/pending", Auth: authDashboard, Handler: w.apiHITLPending},
		{Method: http.MethodPost, Path: "/api/hitl/decide", Auth: authDashboard, Handler: w.apiHITLDecide},
		{Method: http.MethodPost, Path: "/api/oauth/start", Auth: authDashboard, Handler: w.apiOAuthStart},
		{Method: http.MethodPost, Path: "/api/oauth/exchange", Auth: authDashboard, Handler: w.apiOAuthExchange},
		{Method: http.MethodPost, Path: "/api/oauth/device-poll", Auth: authDashboard, Handler: w.apiOAuthDevicePoll},
		{Method: http.MethodPost, Path: "/api/oauth/revoke", Auth: authDashboard, Handler: w.apiOAuthRevoke},
		{Method: http.MethodPost, Path: "/api/tailscale/connect", Auth: authDashboard, Handler: w.apiTailscaleConnect},
		{Method: http.MethodGet, Path: "/api/tailscale/status", Auth: authDashboard, Handler: w.apiTailscaleStatus},
		{Method: http.MethodPost, Path: "/api/tailscale/disconnect", Auth: authDashboard, Handler: w.apiTailscaleDisconnect},
		{Method: http.MethodPost, Path: "/api/credentials/set", Auth: authDashboard, Handler: w.apiCredentialsSet},
		{Method: http.MethodPost, Path: "/api/credentials/clear", Auth: authDashboard, Handler: w.apiCredentialsClear},
		{Method: http.MethodGet, Path: "/api/events", Auth: authDashboard, Handler: w.apiEventsSSE},
		{Method: http.MethodPost, Path: "/api/actions/", Auth: authDashboard, Handler: w.apiActionByID},
		{Method: http.MethodGet, Path: "/api/analytics", Auth: authDashboard, Handler: w.apiAnalytics},
		{Method: http.MethodGet, Path: "/api/facets", Auth: authDashboard, Handler: w.apiFacets},
		{Method: http.MethodPost, Path: "/api/onboard/start", Auth: authPublic, Handler: w.apiOnboardStart},
		{Method: http.MethodPost, Path: "/api/onboard/poll", Auth: authPublic, Handler: w.apiOnboardPoll},
		{Method: http.MethodPost, Path: "/api/onboard/approve", Auth: authDashboardOrTailnetOperator, Handler: w.apiOnboardApprove},
		{Method: http.MethodGet, Path: "/api/onboard/lookup", Auth: authTailnetOperator, Handler: w.apiOnboardLookup},
		{Method: http.MethodPost, Path: "/api/onboard/claim", Auth: authPublic, Handler: w.apiOnboardClaim},
		{Method: http.MethodGet, Path: "/api/env-pushdown", Auth: authSelfAuthenticating, Handler: w.apiEnvPushdown},
		{Method: http.MethodPost, Path: "/api/peer/ephemeral", Auth: authSelfAuthenticating, Handler: w.apiEphemeralPeer},
		{Method: http.MethodGet, Path: "/__login", Auth: authTailnetOperator, Handler: w.apiDashboardLogin},
	}
}

// dashboardSecretGate requires every non-public request to carry the
// configured dashboard_secret (cookie / header). Onboarding
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
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		secret := w.g.cfg.DashboardSecret
		if secret == "" {
			if dashboardMisconfigAlwaysOpen(r.URL.Path) {
				next.ServeHTTP(rw, r)
				return
			}
			if w.g.cfg.InsecureNoDashboardSecret {
				next.ServeHTTP(rw, r.WithContext(contextWithPrincipal(r.Context(), w.dashboardSecretPrincipal())))
				return
			}
			renderDashboardMisconfigured(rw, r)
			return
		}
		if w.skipsDashboardSecret(r.URL.Path) {
			next.ServeHTTP(rw, r)
			return
		}
		if checkDashboardSecret(r, secret) {
			next.ServeHTTP(rw, r.WithContext(contextWithPrincipal(r.Context(), w.dashboardSecretPrincipal())))
			return
		}
		if w.mayUseTailnetInsteadOfDashboard(r.URL.Path) {
			next.ServeHTTP(rw, r)
			return
		}
		// API callers see 401; browsers get redirected to the login form.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(rw, "dashboard secret required", http.StatusUnauthorized)
			return
		}
		http.Redirect(rw, r, "/__login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

func dashboardMisconfigAlwaysOpen(path string) bool {
	return path == "/info" || path == "/ca.crt"
}

const dashboardMisconfiguredMsg = "dashboard refuses to serve: gateway.hcl is missing both `dashboard_secret` and `insecure_no_dashboard_secret`. Set `dashboard_secret = \"<long random string>\"` to require a password, or `insecure_no_dashboard_secret = true` to explicitly run without auth (testing only)."

func renderDashboardMisconfigured(rw http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(rw, dashboardMisconfiguredMsg, http.StatusServiceUnavailable)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprintf(rw, `<!doctype html>
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
	renderLogin(rw, next, "", 200)
}

func renderLogin(rw http.ResponseWriter, next, errMsg string, status int) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	_ = loginTpl.Execute(rw, struct{ Next, Error string }{next, errMsg})
}

// tailnetGate restricts non-tailnet callers to routes whose centralized
// auth policy is authPublic. Dashboard, status, OAuth, event streams, and
// self-authenticating routes keep the existing tailnet behavior.
func (w *webMux) tailnetGate(next http.Handler) http.Handler {
	// In wireguard / proxy mode there is no tailnet identity to gate
	// against. Operators put the dashboard behind their own
	// authentication (Cloudflare Access, basic auth proxy, etc).
	skipGate := !isTailscaleControlMode(w.g.cfg.Control)

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.skipsTailnetGate(r.URL.Path) || skipGate {
			next.ServeHTTP(rw, r)
			return
		}
		if w.authRequirementForPath(r.URL.Path) == authDashboardOrTailnetOperator {
			if _, ok := principalFromContext(r.Context()); ok {
				next.ServeHTTP(rw, r)
				return
			}
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
		var login, device, displayHost string
		if w.g.agents != nil {
			if who := w.g.agents.lookupWhois(host); who != nil {
				login = who.UserProfile.LoginName
				device = who.Node.StableID
				displayHost = who.Node.HostName
			}
		}
		if login == "" && isLoopback(host) {
			// `tailscale serve` proxy hop. The header is authoritative
			// here because nothing public can reach loopback.
			login = r.Header.Get("Tailscale-User-Login")
			displayHost = host
		}
		if login == "" {
			http.Error(rw, "tailnet access required — onboard via `clawpatrol join <gateway>`", http.StatusForbidden)
			return
		}
		principal := principal{Kind: principalTailnet, Owner: login, User: login, Device: device, Host: displayHost}
		next.ServeHTTP(rw, r.WithContext(contextWithPrincipal(r.Context(), principal)))
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
	_, _ = fmt.Fprintf(rw, `{"clawpatrol":true,"version":"0.1"}`+"\n")
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

// credentialProfileKeyForRequest returns the credentials.profile key used when
// dashboard requests read or write OAuth/secret rows. Prefer an explicit
// profile selector, then the configured default policy profile. The remaining
// fallbacks preserve legacy single-user/per-caller credential keys; they are
// not necessarily declared policy profiles and must not be used as evidence
// that the caller is authenticated.
func (w *webMux) credentialProfileKeyForRequest(r *http.Request) (key, label string) {
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
		"whoami":           w.whoamiData(r),
		"integrations":     w.statusList(r),
		"agents":           w.agentsList(),
		"update":           currentUpdateBanner.Load(),
		"read_only_config": w.g.readOnlyConfig,
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
	_, _ = rw.Write(body)
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
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
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
		body.Owner, _ = w.credentialProfileKeyForRequest(r)
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
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
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
		body.Owner, _ = w.credentialProfileKeyForRequest(r)
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
// Writes must go through /api/config/preview + /api/config/save so
// operators can review the formatted diff before the atomic write.
func (w *webMux) apiConfig(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		b, err := os.ReadFile(w.g.cfgPath)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rev := revisionForBytes(b)
		rw.Header().Set("ETag", `"`+rev+`"`)
		rw.Header().Set("X-Config-Revision", rev)
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = rw.Write(b)
	case "PUT":
		http.Error(rw, "use /api/config/preview then /api/config/save", http.StatusMethodNotAllowed)
	default:
		http.Error(rw, "GET or PUT", http.StatusMethodNotAllowed)
	}
}

func (w *webMux) apiConfigPreview(rw http.ResponseWriter, r *http.Request) {
	if w.g.readOnlyConfig {
		http.Error(rw, "read-only config", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	formatted, err := validateAndFormatConfig(body)
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	w.mu.Lock()
	var current []byte
	var rev string
	var token string
	if err := withConfigFileLock(w.g.cfgPath, func() error {
		current, err = os.ReadFile(w.g.cfgPath)
		if err != nil {
			return err
		}
		rev = revisionForBytes(current)
		token, err = newConfigPreviewToken()
		if err != nil {
			return err
		}
		w.configPreviewTokens()[token] = configPreviewToken{
			revision:    rev,
			contentHash: revisionForBytes(formatted),
		}
		return nil
	}); err != nil {
		w.mu.Unlock()
		http.Error(rw, err.Error(), 500)
		return
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]any{
		"ok":            true,
		"formatted":     string(formatted),
		"diff":          unifiedDiff("gateway.hcl", "formatted draft", string(current), string(formatted)),
		"changed":       !bytes.Equal(current, formatted),
		"bytes":         len(formatted),
		"revision":      rev,
		"preview_token": token,
	})
}

func (w *webMux) apiConfigSave(rw http.ResponseWriter, r *http.Request) {
	if w.g.readOnlyConfig {
		http.Error(rw, "read-only config", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Content          string `json:"content"`
		ExpectedRevision string `json:"expected_revision"`
		PreviewToken     string `json:"preview_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ExpectedRevision == "" {
		http.Error(rw, "expected_revision required", 400)
		return
	}
	if body.PreviewToken == "" {
		http.Error(rw, "preview_token required", 400)
		return
	}
	formatted, err := validateAndFormatConfig([]byte(body.Content))
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	preview, ok := w.configPreviewTokens()[body.PreviewToken]
	if !ok {
		http.Error(rw, "preview token not found; review changes before saving", http.StatusPreconditionRequired)
		return
	}
	if preview.revision != body.ExpectedRevision || preview.contentHash != revisionForBytes(formatted) {
		http.Error(rw, "preview token does not match reviewed content", http.StatusPreconditionFailed)
		return
	}
	if err := withConfigFileLock(w.g.cfgPath, func() error {
		currentRev, err := fileRevision(w.g.cfgPath)
		if err != nil {
			return err
		}
		if body.ExpectedRevision != currentRev {
			return errConfigRevisionConflict
		}
		if err := writeConfigAtomically(w.g.cfgPath, formatted); err != nil {
			return err
		}
		delete(w.previews, body.PreviewToken)
		return nil
	}); err != nil {
		if errors.Is(err, errConfigRevisionConflict) {
			http.Error(rw, "gateway.hcl changed since preview; reload before saving", http.StatusConflict)
			return
		}
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"ok": true, "bytes": len(formatted), "revision": revisionForBytes(formatted)})
}

func validateAndFormatConfig(body []byte) ([]byte, error) {
	if _, diags := config.LoadBytes(body, "gateway.hcl"); diags.HasErrors() {
		return nil, fmt.Errorf("hcl: %s", diags.Error())
	}
	formatted := hclwrite.Format(body)
	if _, diags := config.LoadBytes(formatted, "gateway.hcl"); diags.HasErrors() {
		return nil, fmt.Errorf("formatted hcl: %s", diags.Error())
	}
	return formatted, nil
}

func withConfigFileLock(configPath string, fn func() error) error {
	lockPath := configPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer func() { _ = lockFile.Close() }()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func writeConfigAtomically(path string, body []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

func fileRevision(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return revisionForBytes(b), nil
}

func revisionForBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (w *webMux) configPreviewTokens() map[string]configPreviewToken {
	if w.previews == nil {
		w.previews = map[string]configPreviewToken{}
	}
	return w.previews
}

func newConfigPreviewToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("preview token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

type diffOp struct {
	prefix  byte
	line    string
	oldLine int
	newLine int
}

const maxUnifiedDiffCells = 4_000_000 // ~32 MiB DP table on 64-bit Go; covers ~2k x ~2k line configs.

func unifiedDiff(oldName, newName, oldText, newText string) string {
	if oldText == newText {
		return ""
	}
	oldLines := splitDiffLines(oldText)
	newLines := splitDiffLines(newText)
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", oldName, newName)

	if len(oldLines) > 0 && len(newLines) > 0 && len(oldLines) > maxUnifiedDiffCells/len(newLines) {
		fmt.Fprintf(&b, "@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines))
		for _, line := range oldLines {
			b.WriteByte('-')
			b.WriteString(line)
			b.WriteByte('\n')
		}
		for _, line := range newLines {
			b.WriteByte('+')
			b.WriteString(line)
			b.WriteByte('\n')
		}
		return b.String()
	}

	dp := make([][]int, len(oldLines)+1)
	for i := range dp {
		dp[i] = make([]int, len(newLines)+1)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	ops := make([]diffOp, 0, len(oldLines)+len(newLines))
	for i, j := 0, 0; i < len(oldLines) || j < len(newLines); {
		switch {
		case i < len(oldLines) && j < len(newLines) && oldLines[i] == newLines[j]:
			ops = append(ops, diffOp{prefix: ' ', line: oldLines[i], oldLine: i + 1, newLine: j + 1})
			i++
			j++
		case i < len(oldLines) && (j == len(newLines) || dp[i+1][j] >= dp[i][j+1]):
			ops = append(ops, diffOp{prefix: '-', line: oldLines[i], oldLine: i + 1, newLine: j + 1})
			i++
		case j < len(newLines):
			ops = append(ops, diffOp{prefix: '+', line: newLines[j], oldLine: i + 1, newLine: j + 1})
			j++
		}
	}

	const contextLines = 3
	for start := 0; start < len(ops); {
		for start < len(ops) && ops[start].prefix == ' ' {
			start++
		}
		if start >= len(ops) {
			break
		}

		hunkStart := max(start-contextLines, 0)
		lastChange := start
		end := min(start+contextLines+1, len(ops))
		for scan := start + 1; scan < len(ops); scan++ {
			if ops[scan].prefix == ' ' {
				continue
			}
			if scan > end+contextLines {
				break
			}
			lastChange = scan
			end = min(scan+contextLines+1, len(ops))
		}

		writeDiffHunk(&b, ops[hunkStart:end])
		start = lastChange + 1
	}

	return b.String()
}

func writeDiffHunk(b *strings.Builder, ops []diffOp) {
	if len(ops) == 0 {
		return
	}
	oldStart, newStart := 0, 0
	oldCount, newCount := 0, 0
	for _, op := range ops {
		if oldStart == 0 && op.prefix != '+' {
			oldStart = op.oldLine
		}
		if newStart == 0 && op.prefix != '-' {
			newStart = op.newLine
		}
		if op.prefix != '+' {
			oldCount++
		}
		if op.prefix != '-' {
			newCount++
		}
	}
	if oldStart == 0 {
		oldStart = ops[0].oldLine
	}
	if newStart == 0 {
		newStart = ops[0].newLine
	}

	fmt.Fprintf(b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
	for _, op := range ops {
		b.WriteByte(op.prefix)
		b.WriteString(op.line)
		b.WriteByte('\n')
	}
}

func splitDiffLines(s string) []string {
	trimmed := strings.TrimSuffix(s, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
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
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
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
	owner, _ := w.credentialProfileKeyForRequest(r)
	if owner == "" {
		http.Error(rw, "profile required", http.StatusForbidden)
		return
	}
	out, refused, err := generateRuleHCL(r.Context(), w.g, body.Agent, owner, body.Prompt, body.CurrentYAML, body.Scope)
	if err != nil {
		http.Error(rw, "ai: "+err.Error(), http.StatusBadGateway)
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
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
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
	principal, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(rw, "decision requires an authenticated operator", http.StatusForbidden)
		return
	}
	ok = w.g.hitl.Decide(body.ID, runtime.HITLDecision{Allow: body.Allow, By: principal.Owner})
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
		_, _ = fmt.Fprintf(rw, ": no sink\n\n")
		flusher.Flush()
		return
	}
	backlog, ch, cancel := w.g.sink.RecentAndSubscribe()
	defer cancel()

	_, _ = fmt.Fprint(rw, ": connected\n\n")
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
				_, _ = fmt.Fprintf(rw, "event: backlog\ndata: %s\n\n", b)
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
			_, _ = fmt.Fprint(rw, ": ka\n\n")
			flusher.Flush()
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			if wantIP != "" && pkt.ev.AgentIP != wantIP {
				continue
			}
			_, _ = fmt.Fprintf(rw, "data: %s\n\n", pkt.raw)
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
		family      sql.NullString
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
		extra       sql.NullString
		endpoint    sql.NullString
		rule        sql.NullString
	)
	err := w.g.db.QueryRow(`
		SELECT ts_ns, mode, family, agent_ip, host, method, path,
		       status, bytes_in, bytes_out, ms, action,
		       reason, req_sha, resp_sha,
		       req_body, resp_body,
		       req_headers, resp_headers, extra,
		       endpoint, rule
		FROM actions WHERE action_id = ?`, actionID,
	).Scan(
		&tsNs, &mode, &family, &agentIP, &e.Host,
		&method, &path, &status, &in, &ot, &ms,
		&action, &reason, &reqSha, &respSha,
		&reqBody, &respBody,
		&reqHeaders, &respHeaders, &extra,
		&endpoint, &rule,
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
	e.Family = family.String
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
	if extra.String != "" {
		_ = json.Unmarshal([]byte(extra.String), &e.Facets)
	}
	e.Endpoint = endpoint.String
	e.Rule = rule.String
	if r.URL.Query().Get("fmt") == "fixture" {
		w.writeActionFixture(rw, &e)
		return
	}
	writeJSON(rw, e)
}

// writeActionFixture emits the Action JSON for `clawpatrol test`
// (site/doc/clawpatrol-test.md). 400s on events that pre-date
// endpoint tracking or can't be mapped to a terminal verdict.
func (w *webMux) writeActionFixture(rw http.ResponseWriter, ev *Event) {
	policy := w.g.Policy()
	if policy == nil {
		http.Error(rw, "policy not loaded", 503)
		return
	}
	if ev.Endpoint == "" {
		http.Error(rw, "action predates endpoint tracking; cannot export as fixture", 400)
		return
	}
	ep := policy.Endpoints[ev.Endpoint]
	if ep == nil {
		http.Error(rw, fmt.Sprintf("endpoint %q no longer in policy", ev.Endpoint), 400)
		return
	}
	m, ok := matchFromEvent(ev)
	if !ok {
		http.Error(rw, fmt.Sprintf("event action %q is not exportable as a fixture", ev.Action), 400)
		return
	}

	fx := &Fixture{Match: m, Action: Action{PeerIP: ev.AgentIP}}
	switch ep.Family {
	case "http":
		fx.Action.Host = ev.Host
		fx.Action.HTTP = exportHTTP(ev)
	case "k8s":
		fx.Action.Host = ev.Host
		fx.Action.K8s = exportK8s(ev)
	case "sql":
		sql := exportSQL(ev)
		if sql == nil {
			http.Error(rw, "sql action has no statement recorded; cannot export", 400)
			return
		}
		// Host for SQL comes from the endpoint's HCL declaration —
		// the recorded Event.Host is the dst IP / tunnel listener,
		// not what the resolver scans against. For multi-host
		// endpoints pick the first; the runner short-circuits on
		// match.endpoint anyway, so host is informational here.
		if len(ep.Hosts) > 0 {
			fx.Action.Host = ep.Hosts[0]
		}
		fx.Action.SQL = sql
	default:
		http.Error(rw, fmt.Sprintf("endpoint family %q is not yet exportable", ep.Family), 501)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, ev.ID))
	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")
	_ = enc.Encode(fx)
}

// matchFromEvent maps post-chain Event.Action onto the fixture's
// terminal verdict vocabulary. hitl_* collapses to "approve".
// Empty Event.Action maps to "allow" — that's the legacy default
// for rows written before per-action verdicts were tracked.
func matchFromEvent(ev *Event) (Match, bool) {
	m := Match{Rule: ev.Rule, Endpoint: ev.Endpoint, Reason: ev.Reason}
	switch ev.Action {
	case "deny":
		m.Verdict = "deny"
	case "hitl_allow", "hitl_deny":
		m.Verdict = "approve"
	case "allow", "":
		m.Verdict = "allow"
	case "passthrough":
		m.Verdict = "passthrough"
	default:
		return Match{}, false
	}
	return m, true
}

// exportHTTP populates the http.* CEL view from a recorded Event.
// Host lives on Action (not in the http block) since `http.host`
// isn't a CEL variable. Path comes straight from the recorded URL.
func exportHTTP(ev *Event) *HTTPAction {
	body, b64 := encodeBody([]byte(ev.ReqBody))
	path, query := splitPathQuery(ev.Path)
	return &HTTPAction{
		Method:  ev.Method,
		Path:    path,
		Query:   query,
		Headers: headersToMultiValue(ev.ReqHeaders),
		Body:    body,
		BodyB64: b64,
	}
}

// splitPathQuery separates a recorded Event.Path (which may carry
// `?query=...` already encoded) into path + parsed-query.
func splitPathQuery(raw string) (string, map[string][]string) {
	q := strings.IndexByte(raw, '?')
	if q < 0 {
		return raw, nil
	}
	vals, err := url.ParseQuery(raw[q+1:])
	if err != nil || len(vals) == 0 {
		return raw[:q], nil
	}
	return raw[:q], vals
}

// exportK8s recovers the parsed k8s tuple from Event.Facets, set
// by the k8s facet's Report at live-dispatch time. Only CEL-visible
// fields land in the k8s block.
func exportK8s(ev *Event) *K8sAction {
	a := &K8sAction{}
	if v, ok := ev.Facets["verb"].(string); ok {
		a.Verb = v
	}
	if v, ok := ev.Facets["resource"].(string); ok {
		a.Resource = v
	}
	if v, ok := ev.Facets["namespace"].(string); ok {
		a.Namespace = v
	}
	if v, ok := ev.Facets["name"].(string); ok {
		a.Name = v
	}
	if p, ok := ev.Facets["params"].(map[string]any); ok {
		a.Params = map[string]string{}
		for k, val := range p {
			if s, ok := val.(string); ok {
				a.Params[k] = s
			}
		}
	}
	return a
}

// exportSQL pulls the raw statement out of Event.Facets (set by
// sqlfacet.Report). The loader re-derives verb / tables / function
// from the statement via SQLParser at replay time.
func exportSQL(ev *Event) *SQLAction {
	stmt, _ := ev.Facets["statement"].(string)
	if stmt == "" {
		return nil
	}
	return &SQLAction{Statement: stmt}
}

// headersToMultiValue widens the Sink's single-value header map to
// http.Header's multi-value shape.
func headersToMultiValue(h map[string]string) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[k] = []string{v}
	}
	return out
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
		SELECT action_id, ts_ns, mode, family, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason, extra
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
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, 256)
	for rows.Next() {
		var (
			e        Event
			actionID sql.NullString
			tsNs     int64
			mode     sql.NullString
			family   sql.NullString
			agentIP  sql.NullString
			method   sql.NullString
			path     sql.NullString
			status   sql.NullInt64
			in, ot   sql.NullInt64
			ms       sql.NullInt64
			action   sql.NullString
			reason   sql.NullString
			extra    sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &family, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason, &extra,
		); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		e.ID = actionID.String
		e.Ts = time.Unix(0, tsNs).UTC()
		e.Mode = mode.String
		e.Family = family.String
		e.AgentIP = agentIP.String
		e.Method = method.String
		e.Path = path.String
		e.Status = int(status.Int64)
		e.In = in.Int64
		e.Out = ot.Int64
		e.Ms = ms.Int64
		e.Action = action.String
		e.Reason = reason.String
		if extra.String != "" {
			_ = json.Unmarshal([]byte(extra.String), &e.Facets)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		http.Error(rw, err.Error(), 500)
		return
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

// apiFacets returns every registered facet's reporting schema.
// The dashboard fetches this once at boot and uses it to render
// per-family columns (HTTPS: method/path/status, SQL:
// verb/tables/..., k8s: verb/resource/...) directly from the JSON
// `facets` payload on each event, instead of carrying a hardcoded
// switch on family strings.
func (w *webMux) apiFacets(rw http.ResponseWriter, r *http.Request) {
	_ = r
	type reportFieldJSON struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Label string `json:"label,omitempty"`
	}
	type facetJSON struct {
		Name             string            `json:"name"`
		EndpointFamilies []string          `json:"endpoint_families"`
		Transport        string            `json:"transport,omitempty"`
		HITLQueryLabel   string            `json:"hitl_query_label,omitempty"`
		HostIsResource   bool              `json:"host_is_resource"`
		ReportFields     []reportFieldJSON `json:"report_fields"`
	}
	all := facet.All()
	out := make([]facetJSON, 0, len(all))
	for _, f := range all {
		fks := f.ReportFields()
		entry := facetJSON{
			Name:             f.Name(),
			EndpointFamilies: f.EndpointFamilies(),
			Transport:        f.Transport(),
			HITLQueryLabel:   f.HITLQueryLabel(),
			HostIsResource:   f.HostIsResource(),
			ReportFields:     make([]reportFieldJSON, len(fks)),
		}
		for i, fk := range fks {
			entry.ReportFields[i] = reportFieldJSON{
				Name: fk.Name, Kind: reportKindName(fk.Kind), Label: fk.Label,
			}
		}
		out = append(out, entry)
	}
	writeJSON(rw, map[string]any{"facets": out})
}

func reportKindName(k facet.ReportValueKind) string {
	switch k {
	case facet.ReportString:
		return "string"
	case facet.ReportStringList:
		return "string_list"
	case facet.ReportStringMap:
		return "string_map"
	case facet.ReportInt:
		return "int"
	}
	return ""
}

func groupCount(db *sql.DB, q string, args []any) []map[string]any {
	out := []map[string]any{}
	rows, err := db.Query(q, args...)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
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
	if err := rows.Err(); err != nil {
		return []map[string]any{}
	}
	return out
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(v)
}

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

	// Family identifies which protocol-family facet emitted this
	// event ("http", "sql", "k8s", or a future plugin's name).
	// Persisted as a dedicated column on actions so analytics can
	// filter by family; drives dashboard column selection via
	// /api/facets. Empty for splice events and pre-migration rows.
	Family string `json:"family,omitempty"`

	// Facets carries the per-family report payload — the result of
	// the family's facet.Runtime.Report hook against the matched
	// request. Keys correspond to the family's ReportFields().
	// Serialised as JSON into the actions table's `extra` column.
	Facets map[string]any `json:"facets,omitempty"`

	// Endpoint is the dispatching CompiledEndpoint.Name; Rule is the
	// matched CompiledRule.Name (empty when no rule fired). Populated
	// at the existing dispatch sites so the action-fixture exporter
	// can pin a downloaded action to a specific endpoint and assert
	// the rule that produced its verdict (site/doc/clawpatrol-test.md).
	Endpoint string `json:"endpoint,omitempty"`
	Rule     string `json:"rule,omitempty"`
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
		SELECT action_id, ts_ns, mode, family, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason, req_sha, resp_sha, extra,
		       endpoint, rule
		FROM actions ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, n)
	for rows.Next() {
		var (
			e        Event
			actionID sql.NullString
			tsNs     int64
			mode     sql.NullString
			family   sql.NullString
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
			extra    sql.NullString
			endpoint sql.NullString
			rule     sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &family, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason, &reqSha, &respSha, &extra,
			&endpoint, &rule,
		); err != nil {
			return nil, err
		}
		e.ID = actionID.String
		e.Ts = time.Unix(0, tsNs).UTC()
		e.Mode = mode.String
		e.Family = family.String
		e.Endpoint = endpoint.String
		e.Rule = rule.String
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
		if extra.String != "" {
			_ = json.Unmarshal([]byte(extra.String), &e.Facets)
		}
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
			var extraJSON []byte
			if len(e.Facets) > 0 {
				extraJSON, _ = json.Marshal(e.Facets)
			}
			_, _ = s.db.Exec(`
				INSERT INTO actions
				 (action_id, ts_ns, mode, family, agent_ip, host,
				  method, path, status, bytes_in, bytes_out,
				  ms, action, reason, req_sha, resp_sha,
				  req_body, resp_body,
				  req_headers, resp_headers, extra,
				  endpoint, rule)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			`, e.ID, e.Ts.UnixNano(), e.Mode, e.Family, e.AgentIP,
				e.Host, e.Method, e.Path, e.Status,
				e.In, e.Out, e.Ms, e.Action, e.Reason,
				e.ReqSha, e.RespSha,
				e.ReqBody, e.RespBody,
				string(rqhJSON), string(rshJSON),
				string(extraJSON),
				e.Endpoint, e.Rule)
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

// sample returns the audit-log preview of the captured body. When
// encoding names a compression we know how to decode (currently only
// gzip — the encoding most agents request via Accept-Encoding and
// most upstreams reply with), the buffered prefix is decompressed
// first so a JSON response doesn't get rendered as "binary:<hex>"
// just because it's still on the wire as gzip.
func (s *sampler) sample(encoding string) string {
	if s.buf.Len() == 0 {
		return ""
	}
	raw := s.buf.Bytes()
	body := maybeDecode(raw, encoding)
	if isPrintable(body) {
		return string(body)
	}
	return "binary:" + hex.EncodeToString(raw[:min(64, len(raw))])
}

// maybeDecode returns the decompressed prefix of buf when encoding is
// gzip, or buf unchanged otherwise. The sampler captures at most cap
// bytes, so the gzip stream is almost always truncated mid-block —
// io.ReadAll returns whatever the reader managed before hitting
// io.ErrUnexpectedEOF, which is exactly what we want for a preview.
func maybeDecode(buf []byte, encoding string) []byte {
	if !strings.EqualFold(strings.TrimSpace(encoding), "gzip") {
		return buf
	}
	zr, err := gzip.NewReader(bytes.NewReader(buf))
	if err != nil {
		return buf
	}
	defer func() { _ = zr.Close() }()
	out, _ := io.ReadAll(zr)
	if len(out) == 0 {
		return buf
	}
	return out
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
