package main

// dashboardAuthGate + tailnetGate are the two HTTP middlewares the
// dashboard mux mounts above every protected route. The gate file
// keeps them next to the /__login + /__logout handlers and the
// session-cookie minting helpers, since changes to one almost always
// ripple into another and reading them side-by-side is what reveals
// whether the dashboard's auth surface is still consistent.
//
// See doc/security-model.md for the full trust statement. The short
// version: the password gate runs first and short-circuits when a
// valid cp_session cookie is presented; tailnet identity is consulted
// when the password path can't decide on its own.

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// cpSessionCookieName holds an opaque, server-issued session token —
// random 256 bits, never derived from the password. The cookie is
// HttpOnly + SameSite=Lax. The DB only stores its SHA-256, so a DB
// leak doesn't grant access. Replaces the older cp_dash cookie that
// stored the raw password.
const cpSessionCookieName = "cp_session"

// dashboardLoginPath is the unauthenticated login + first-run setup
// endpoint. Single route to keep the auth surface small.
const dashboardLoginPath = "/__login"

// dashboardMinPasswordLen is the minimum length enforced at password
// set time. 12 chars is the OWASP-recommended floor for human-chosen
// passwords; the CLI flag enforces the same limit.
const dashboardMinPasswordLen = 12

// dashboardSessionTTL resolves the configured session TTL or falls
// back to the default. Validator catches bad strings at load time;
// the duplicate parse here is so a hot-reloaded config can change
// the TTL without restarting.
func (w *webMux) dashboardSessionTTL() time.Duration {
	d, err := config.DashboardSessionTTLFromString(w.g.cfg.DashboardSessionTTL())
	if err != nil {
		// Validator at config load would have caught this; defensive
		// fallback to the default keeps a hot-reload typo from
		// breaking the login flow.
		return config.DefaultDashboardSessionTTL
	}
	return d
}

func (w *webMux) dashboardAuthGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// /info, /ca.crt, /api/onboard/{start,poll,claim} stay open
		// for brand-new clients that don't have any credential yet.
		if w.skipsDashboardPassword(path) {
			next.ServeHTTP(rw, r)
			return
		}

		// First-run gate: until a root row exists, every protected
		// request redirects to /__login (which renders the "set
		// password" form). API callers see 401 with a hint.
		_, rootExists, err := lookupDashboardUser(w.g.db, dashboardRootUsername)
		if err != nil {
			http.Error(rw, "dashboard auth lookup failed", http.StatusServiceUnavailable)
			return
		}
		if !rootExists {
			if path == dashboardLoginPath {
				next.ServeHTTP(rw, r)
				return
			}
			if strings.HasPrefix(path, "/api/") {
				http.Error(rw, "dashboard not initialized — open the dashboard and set a password, or run `clawpatrol gateway --set-dashboard-password <pw>`", http.StatusUnauthorized)
				return
			}
			http.Redirect(rw, r, dashboardLoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}

		// Session-cookie path: look up the cookie's token-hash in
		// the dashboard_sessions table. Hit → inject the password
		// principal so tailnetGate downstream short-circuits.
		if username := w.lookupSessionFromRequest(r); username != "" {
			next.ServeHTTP(rw, r.WithContext(contextWithPrincipal(r.Context(), w.dashboardPasswordPrincipal())))
			return
		}

		// Tailnet allowlist path: defer to tailnetGate so it can
		// resolve the whois identity and compare against the
		// configured operators allowlist. Only relevant when the
		// `tailscale {}` block is enabled — without it there's no
		// whois identity to resolve.
		if w.g.cfg.IsTailscaleEnabled() && len(w.g.cfg.Operators()) > 0 {
			next.ServeHTTP(rw, r)
			return
		}

		// /api/onboard/approve in tailscale-control mode is a
		// dual-path route (any tailnet operator can approve), so
		// pass it through to tailnetGate even without a configured
		// allowlist.
		if w.mayUseTailnetInsteadOfDashboard(path) {
			next.ServeHTTP(rw, r)
			return
		}

		// API callers see 401; browsers get redirected to the login form.
		if strings.HasPrefix(path, "/api/") {
			http.Error(rw, "dashboard session required", http.StatusUnauthorized)
			return
		}
		http.Redirect(rw, r, dashboardLoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

// lookupSessionFromRequest reads the cp_session cookie, looks up the
// matching row, and returns the username on a live hit. Empty string
// when missing/expired/error (the gate treats all three as "no
// session, redirect to login").
func (w *webMux) lookupSessionFromRequest(r *http.Request) string {
	c, err := r.Cookie(cpSessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	username, ok, err := lookupDashboardSession(w.g.db, c.Value)
	if err != nil || !ok {
		return ""
	}
	return username
}

func safeDashboardLoginNext(next string) string {
	if next == "" || strings.Contains(next, "\\") || strings.HasPrefix(next, "//") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	return next
}

// apiDashboardLogin serves /__login. Two modes, switched on whether
// the root row exists:
//
//   - first-run (GET): render the "set password" form (two fields).
//     POST: validate password == confirm, length >= 12, upsert root,
//     mint a session, set cookie, redirect.
//   - steady-state (GET): render the "enter password" form.
//     POST: bcrypt-verify, mint a session, set cookie, redirect.
func (w *webMux) apiDashboardLogin(rw http.ResponseWriter, r *http.Request) {
	next := safeDashboardLoginNext(r.URL.Query().Get("next"))
	_, rootExists, err := lookupDashboardUser(w.g.db, dashboardRootUsername)
	if err != nil {
		http.Error(rw, "dashboard auth lookup failed", http.StatusServiceUnavailable)
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(rw, "bad form", http.StatusBadRequest)
			return
		}
		password := r.PostFormValue("password")
		if !rootExists {
			confirm := r.PostFormValue("confirm")
			if len(password) < dashboardMinPasswordLen {
				renderLogin(rw, next, fmt.Sprintf("password must be at least %d characters", dashboardMinPasswordLen), true, http.StatusBadRequest)
				return
			}
			if password != confirm {
				renderLogin(rw, next, "passwords do not match", true, http.StatusBadRequest)
				return
			}
			if err := setDashboardUser(w.g.db, dashboardRootUsername, password); err != nil {
				log.Printf("set dashboard root password: %v", err)
				http.Error(rw, "could not store password", http.StatusInternalServerError)
				return
			}
			log.Printf("dashboard auth: root password initialized via /__login first-run flow")
			if err := w.mintAndSetSessionCookie(rw, dashboardRootUsername); err != nil {
				http.Error(rw, "could not mint session", http.StatusInternalServerError)
				return
			}
			http.Redirect(rw, r, next, http.StatusFound)
			return
		}
		ok, _, err := checkDashboardPassword(w.g.db, dashboardRootUsername, password)
		if err != nil {
			http.Error(rw, "dashboard auth check failed", http.StatusServiceUnavailable)
			return
		}
		if !ok {
			renderLogin(rw, next, "wrong password", false, http.StatusUnauthorized)
			return
		}
		if err := w.mintAndSetSessionCookie(rw, dashboardRootUsername); err != nil {
			http.Error(rw, "could not mint session", http.StatusInternalServerError)
			return
		}
		http.Redirect(rw, r, next, http.StatusFound)
		return
	}
	renderLogin(rw, next, "", !rootExists, http.StatusOK)
}

// apiDashboardLogout revokes the cp_session cookie (server- and
// client-side) and redirects to /__login. Idempotent — POSTing
// without a cookie clears nothing and still 200s. GET / non-tailnet
// callers without a session land here too via the gate; the cookie
// clear is harmless in those cases.
func (w *webMux) apiDashboardLogout(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(cpSessionCookieName); err == nil && c.Value != "" {
		if err := revokeDashboardSession(w.g.db, c.Value); err != nil {
			log.Printf("revoke dashboard session: %v", err)
		}
	}
	// Clear the cookie regardless of whether the row existed — the
	// browser may have a stale value and we want it gone.
	http.SetCookie(rw, &http.Cookie{
		Name:     cpSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	rw.WriteHeader(http.StatusOK)
}

// mintAndSetSessionCookie creates a row in dashboard_sessions for
// username, then writes the raw token to the cp_session cookie. The
// cookie's Max-Age matches the configured TTL — same window the
// server-side row enforces — so the browser stops sending it the
// moment the server stops accepting it.
func (w *webMux) mintAndSetSessionCookie(rw http.ResponseWriter, username string) error {
	ttl := w.dashboardSessionTTL()
	token, err := createDashboardSession(w.g.db, username, ttl)
	if err != nil {
		log.Printf("create dashboard session: %v", err)
		return err
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     cpSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	return nil
}

func renderLogin(rw http.ResponseWriter, next, errMsg string, firstRun bool, status int) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	_ = loginTpl.Execute(rw, struct {
		Next     string
		Error    string
		FirstRun bool
	}{next, errMsg, firstRun})
}

// tailnetGate runs downstream of dashboardAuthGate. Three jobs:
//
//   - For routes the upstream gate already authenticated (password
//     cookie verified), let the request pass with its injected
//     principal.
//   - For authTailnetOperator / authDashboardOrTailnetOperator
//     routes, attribute a principal from the tsnet whois identity
//     ("any tailnet member, just identify them").
//   - For authDashboard routes that fall through here (because the
//     password cookie was missing and DashboardOperators is
//     configured), require that the whois login matches the
//     operator allowlist. This is the path that lets a deployed
//     "alice@example.com" operator hit the dashboard with no
//     password while keeping every other tailnet peer — including
//     tagged agent devices — locked out.
//
// In wireguard / proxy mode there is no tsnet whois at all; the
// gate is skipped and dashboardAuthGate's password requirement is
// the only auth.
func (w *webMux) tailnetGate(next http.Handler) http.Handler {
	skipGate := !w.g.cfg.IsTailscaleEnabled()

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.skipsTailnetGate(r.URL.Path) || skipGate {
			next.ServeHTTP(rw, r)
			return
		}
		// Upstream password gate already authenticated → keep the
		// dashboard principal it injected.
		if _, ok := principalFromContext(r.Context()); ok {
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
		// Operator-class routes — approving onboarding devices, looking
		// up pending user_codes, reading the dashboard via tailnet
		// identity — must require an explicit dashboard_operators
		// allowlist match for the tailnet identity path. Previously
		// authTailnetOperator and authDashboardOrTailnetOperator
		// accepted any non-empty whois, which let tag:client peers
		// (whois == "tagged-devices") call /api/onboard/approve and
		// mint fresh auth keys bound to arbitrary profiles — see
		// issue #509. MatchDashboardOperator only accepts "user@domain"
		// or "*@domain" entries, so "tagged-devices" and "tagged-*"
		// stubs fail closed by construction.
		//
		// The dashboard-password path is unaffected: requests carrying
		// a valid cp_session cookie have their principal injected by
		// dashboardAuthGate upstream and short-circuit this gate at
		// the principalFromContext check above.
		if needsOperatorGate(w.authRequirementForPath(r.URL.Path)) {
			if !config.MatchDashboardOperator(login, w.g.cfg.Operators()) {
				http.Error(rw, "operator routes require a dashboard password session or a tailnet login matching the operators allowlist", http.StatusForbidden)
				return
			}
		}
		principal := principal{Kind: principalTailnet, Owner: login, User: login, Device: device, Host: displayHost}
		next.ServeHTTP(rw, r.WithContext(contextWithPrincipal(r.Context(), principal)))
	})
}

// needsOperatorGate reports whether req requires the caller to be an
// operator — either a dashboard-password session or a tailnet login
// matching dashboard_operators. Every non-public, non-self-auth
// route is operator-class in the daemon-model gateway, because all
// of them either expose internal state or accept profile-affecting
// writes. The dashboard-password path is handled separately by
// dashboardAuthGate; this only applies on the tailnet-identity path.
func needsOperatorGate(req authRequirement) bool {
	switch req {
	case authDashboard, authTailnetOperator, authDashboardOrTailnetOperator:
		return true
	}
	return false
}
