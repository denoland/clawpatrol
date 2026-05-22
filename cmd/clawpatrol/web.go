package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/dashboard"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

var loginTpl = template.Must(template.New("login").Parse(dashboard.LoginHTML))

type webMux struct {
	g         *Gateway
	ts        JoinConfig // for onboarding key minting
	publicURL string
	mu        sync.Mutex
	sessions  map[string]*oauthSession
	onboard   *onboardRegistry
	routeAuth map[string]authRequirement

	// stateCache: per-caller TTL'd memo for /api/state. RWMutex
	// because reads vastly outnumber writes — every dashboard tab
	// polls every 5s, but the cached entry only refreshes once per
	// stateCacheTTL (1s). 99% of polls are RLock-only.
	stateCacheMu sync.RWMutex
	stateCache   map[string]stateCacheEntry
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
	principalDashboardPassword principalKind = "dashboard_password"
	principalTailnet           principalKind = "tailnet"
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

func (w *webMux) dashboardPasswordPrincipal() principal {
	return principal{Kind: principalDashboardPassword, Owner: dashboardRootUsername}
}

func routeAuthIndex(routes []webRoute) map[string]authRequirement {
	out := make(map[string]authRequirement, len(routes))
	for _, route := range routes {
		out[route.Path] = route.Auth
	}
	return out
}

func (w *webMux) authRequirementForPath(path string) authRequirement {
	if strings.HasPrefix(path, credentialWebhookPrefix) || strings.HasPrefix(path, hitlOperationStatusPrefix) {
		return authSelfAuthenticating
	}
	if w.routeAuth != nil {
		if req, ok := w.routeAuth[path]; ok {
			return req
		}
	}
	// The login page is authPublic — its assets must be too, or the
	// browser would chase /claw-patrol-logo.svg through dashboardAuthGate,
	// land on an HTML redirect, and render a broken-image icon on every
	// logged-out visit.
	if isLoginPageAsset(path) {
		return authPublic
	}
	return authDashboard
}

// isLoginPageAsset matches the exact set of static assets the login
// page (www/login.html) loads while the user is unauthenticated:
// favicon, logo, and the woff2 font subset. Anything else under /
// stays gated.
func isLoginPageAsset(path string) bool {
	switch path {
	case "/claw-patrol-icon.svg", "/claw-patrol-logo.svg":
		return true
	}
	return strings.HasPrefix(path, "/fonts/")
}

// skipsDashboardPassword returns true for routes whose handlers
// provide their own authentication (credential webhook signatures,
// peer API tokens) or are intentionally open (/info, /ca.crt,
// onboarding handshakes). For these, the dashboard gate does not
// require the cookie.
func (w *webMux) skipsDashboardPassword(path string) bool {
	switch w.authRequirementForPath(path) {
	case authPublic, authTailnetOperator, authSelfAuthenticating:
		return true
	default:
		return false
	}
}

func (w *webMux) mayUseTailnetInsteadOfDashboard(path string) bool {
	return w.authRequirementForPath(path) == authDashboardOrTailnetOperator &&
		w.g.cfg.IsTailscaleEnabled()
}

func (w *webMux) skipsTailnetGate(path string) bool {
	req := w.authRequirementForPath(path)
	// authPublic needs no gate. authSelfAuthenticating routes carry their
	// own proof (Bearer token, webhook signature) — the tailnet gate would
	// block tag:client devices that have no Tailscale user identity.
	return req == authPublic || req == authSelfAuthenticating
}

func newWebMux(g *Gateway, ts JoinConfig, publicURL string) http.Handler {
	w := &webMux{g: g, ts: ts, publicURL: publicURL, sessions: map[string]*oauthSession{}, onboard: g.onboard}
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
	return w.dashboardAuthGate(w.tailnetGate(mux))
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
		{Method: http.MethodGet, Path: "/api/config", Auth: authDashboard, Handler: w.apiConfig},
		{Method: http.MethodGet, Path: "/api/hitl/pending", Auth: authDashboard, Handler: w.apiHITLPending},
		{Method: http.MethodPost, Path: "/api/hitl/decide", Auth: authDashboard, Handler: w.apiHITLDecide},
		{Method: http.MethodGet, Path: hitlOperationStatusPrefix, Auth: authSelfAuthenticating, Handler: w.apiHITLOperationStatus},
		{Method: http.MethodPost, Path: "/api/oauth/start", Auth: authDashboard, Handler: w.apiOAuthStart},
		{Method: http.MethodPost, Path: "/api/oauth/exchange", Auth: authDashboard, Handler: w.apiOAuthExchange},
		{Method: http.MethodPost, Path: "/api/oauth/device-poll", Auth: authDashboard, Handler: w.apiOAuthDevicePoll},
		{Method: http.MethodPost, Path: "/api/oauth/revoke", Auth: authDashboard, Handler: w.apiOAuthRevoke},
		{Method: http.MethodGet, Path: "/oauth/callback", Auth: authDashboard, Handler: w.serveOAuthCallback},
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
		{Method: http.MethodPost, Path: "/api/peer/tsnet/register", Auth: authSelfAuthenticating, Handler: w.apiPeerTsnetRegister},
		// /__login is the auth point itself — it MUST be reachable
		// without a credential. The handler dispatches on r.Method
		// (GET renders the form, POST validates + mints a session
		// cookie), and dashboardAuthGate further restricts it to
		// first-run mode when no root row exists. SameSite=Lax on
		// the cp_session cookie blocks cross-site CSRF on the POST.
		{Method: http.MethodGet, Path: "/__login", Auth: authPublic, Handler: w.apiDashboardLogin},
		// /__logout revokes the session row + clears the cookie. The
		// gate still applies — only an authenticated caller can log
		// out (tailnet-allowlisted callers get 401 because there's no
		// session to clear; the dashboard SPA disables the button for
		// them rather than calling this endpoint).
		{Method: http.MethodPost, Path: "/__logout", Auth: authDashboard, Handler: w.apiDashboardLogout},
	}
}

// dashboardAuthGate requires every non-public request to carry a
// valid dashboard credential. Two methods are accepted:
//
//   - cookie `cp_dash` (or header `X-Clawpatrol-Secret`) holding the
//     password, bcrypt-checked against the root row in dashboard_users;
//   - in tailscale-control mode, a tsnet whois login that matches an
//     entry in cfg.DashboardOperators. The actual whois resolution
//     happens downstream in tailnetGate; this gate only decides that
//     the request is allowed to reach the tailnet check.
//
// When no root row exists (fresh install), every protected request is
// redirected to /__login, which renders the first-run "set password"
// form. The dashboard cannot serve any management endpoint until a
// password is set, so credentials / profile state can never be
// created before there is an operator to protect them. See
// doc/security-model.md for the full trust statement.
//
// credentialWebhookPrefix is the path prefix every plugin webhook
// route mounts under. Public — credential plugins authenticate
// callbacks via their own signature header (Slack signing secret,
// etc.) so this gate skips the prefix entirely.
const credentialWebhookPrefix = "/api/cred/"

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
		for _, ent := range ep.Credentials {
			if ent == nil || ent.Symbol == nil || credSeen[ent.Symbol.Name] {
				continue
			}
			credSeen[ent.Symbol.Name] = true
			provider, ok := ent.Body.(config.EnvPushdownProvider)
			if !ok {
				continue
			}
			for _, ev := range provider.EnvVars() {
				add(ev.Name, ev.Value, ev.Description, ent.Plugin.Type)
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
	sub, err := fs.Sub(dashboard.DistFS, "dist")
	if err != nil {
		return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "dashboard not built (cd dashboard && npm run build)", 500)
		})
	}
	return http.FileServer(http.FS(sub))
}

func (w *webMux) serveCA(rw http.ResponseWriter, _ *http.Request) {
	pemBytes := w.g.certs.CertPEM()
	if len(pemBytes) == 0 {
		http.Error(rw, "ca not initialized", http.StatusServiceUnavailable)
		return
	}
	rw.Header().Set("Content-Type", "application/x-pem-file")
	rw.Header().Set("Content-Length", strconv.Itoa(len(pemBytes)))
	_, _ = rw.Write(pemBytes)
}

func (w *webMux) serveInfo(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	// Surface the CA fingerprint here so debug tools (and the
	// dashboard's approval page) have a single public-readable
	// liveness + identity endpoint. Same value the OnboardPage
	// renders next to the user_code.
	writeJSON(rw, map[string]any{
		"clawpatrol":     true,
		"version":        "0.1",
		"ca_fingerprint": w.caFingerprint(),
	})
}

// caFingerprint returns the SHA-256 fingerprint of the gateway's
// in-memory CA certificate. Empty when the CA hasn't been minted
// yet (test scaffolding or pre-init) so callers can fall through
// without surfacing a parse error to the operator.
func (w *webMux) caFingerprint() string {
	if w.g == nil || w.g.certs == nil {
		return ""
	}
	pemBytes := w.g.certs.CertPEM()
	if len(pemBytes) == 0 {
		return ""
	}
	fp, err := caFingerprintFromPEM(pemBytes)
	if err != nil {
		return ""
	}
	return fp
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

// selectedProfileForRequest returns the profile name a dashboard request
// targets. Prefer an explicit profile selector, then the configured
// default policy profile. The remaining fallbacks preserve legacy
// single-user/per-caller keys; they are not necessarily declared policy
// profiles and must not be used as evidence that the caller is
// authenticated.
func (w *webMux) selectedProfileForRequest(r *http.Request) (key, label string) {
	if p := r.URL.Query().Get("profile"); p != "" {
		return p, p
	}
	if p := r.Header.Get("X-Clawpatrol-Profile"); p != "" {
		return p, p
	}
	if def := defaultProfileName(w.g.cfg.Policy); def != "" {
		return def, def
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
//
// Source of truth is the principal injected by dashboardAuthGate /
// tailnetGate. For password sessions the principal carries
// {Kind: dashboard_password, Owner: "root"}; for tailnet allowlist
// hits it carries {Kind: tailnet, Owner: <login>, Device, Host}. We
// fall back to the bare whois lookup only when no principal is on
// the context (e.g. on a route the gate let through without one,
// which shouldn't happen for authDashboard but stays defensive).
func (w *webMux) whoamiData(r *http.Request) map[string]string {
	pu := w.g.cfg.PublicURL()
	if pu == "" {
		pu = w.publicURL
	}
	out := map[string]string{
		"user":        "",
		"device":      "",
		"host":        "",
		"auth_method": "",
		"public_url":  pu,
	}
	if p, ok := principalFromContext(r.Context()); ok {
		out["user"] = p.Owner
		out["device"] = p.Device
		out["host"] = p.Host
		switch p.Kind {
		case principalDashboardPassword:
			out["auth_method"] = "password"
		case principalTailnet:
			out["auth_method"] = "tailscale"
		}
		return out
	}
	// No principal on context — fall back to a bare whois so the
	// frontend at least gets a device/host display string. user
	// stays empty so the header renders "not authenticated".
	_, device, host := w.callerIdentity(r)
	out["device"] = device
	out["host"] = host
	return out
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
	// Cache key includes the principal kind + owner so a request
	// authed by the root password and a request authed via tailnet
	// whois don't share an entry — the whoami slice they each render
	// is different.
	var keyKind, keyOwner string
	if p, ok := principalFromContext(r.Context()); ok {
		keyKind = string(p.Kind)
		keyOwner = p.Owner
	}
	cacheKey := keyKind + "|" + keyOwner + "|" + r.URL.Query().Get("profile")
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
		"update":       currentUpdateBanner.Load(),
		"config_file":  filepath.Base(w.g.cfgPath),
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
// credential. Body shape:
//
//	{ "id": "stripe-live", "slots": { "": "sk_live_…" } }
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
				`DELETE FROM credential_secrets WHERE credential = ? AND slot = ?`,
				body.ID, slot,
			); err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
			continue
		}
		if err := setCredentialSlot(w.g.db, body.ID, slot, v); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// apiCredentialsClear drops every slot for the credential. Disconnect
// button on the dashboard.
func (w *webMux) apiCredentialsClear(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	if err := clearCredentialSecrets(w.g.db, body.ID); err != nil {
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
// The gateway is read-only-config — writes happen out-of-band, via
// SSH push from the operator's config repo, not the dashboard.
func (w *webMux) apiConfig(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
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
}

func revisionForBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
	result := runtime.HITLResolveResult{State: runtime.HITLStateUnknown, Reason: "unknown or expired HITL request"}
	decision := runtime.HITLDecision{Allow: body.Allow, By: principal.Owner}
	if decider, ok := interface{}(w.g.hitl).(runtime.HITLPoolDecider); ok {
		result = decider.DecideWithResult(body.ID, decision)
	} else {
		result.OK = w.g.hitl.Decide(body.ID, decision)
		if result.OK {
			if body.Allow {
				result.State = runtime.HITLStateApproved
			} else {
				result.State = runtime.HITLStateDenied
			}
		}
	}
	writeJSON(rw, result)
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

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(v)
}
