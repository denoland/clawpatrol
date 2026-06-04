package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// authTestRootPassword is the seeded root password used by tests
// whose code paths exercise the dashboard auth gate. Bcrypt-hashed
// at setup; tests authenticate by minting a session row directly
// via authTestSessionCookie() and attaching the matching cookie to
// the request.
const authTestRootPassword = "test-dashboard-passphrase-1234"

// authTestSessionCookie creates a real dashboard session for the
// seeded root user and returns the matching cookie. Tests use this
// to present an authenticated request through the gate without
// driving the full /__login form flow.
func authTestSessionCookie(t *testing.T, w *webMux) *http.Cookie {
	t.Helper()
	token, err := createDashboardSession(w.g.db, dashboardRootUsername, w.dashboardSessionTTL())
	if err != nil {
		t.Fatalf("createDashboardSession: %v", err)
	}
	return &http.Cookie{Name: cpSessionCookieName, Value: token}
}

// newOnboardAuthTestWebMux builds a webMux backed by a temporary
// sqlite DB pre-seeded with the root password. Tests that hit
// /api/* through the full handler need this because dashboardAuthGate
// reads from the DB on every request.
func newOnboardAuthTestWebMuxForControl(t *testing.T, control string) *webMux {
	t.Helper()
	db := openOnboardAuthTestDB(t)
	settings := &config.GatewaySettings{}
	switch control {
	case "tailscale", "":
		settings.Tailscale = &config.TailscaleBlock{AuthKey: "tskey-test"}
	case "wireguard":
		settings.WireGuard = &config.WireGuardBlock{SubnetCIDR: "10.55.0.0/24"}
	default:
		t.Fatalf("unknown control %q", control)
	}
	cfg := &config.Gateway{
		Settings: settings,
		Policy:   &config.Policy{},
	}
	g := &Gateway{
		db:      db,
		onboard: newOnboardRegistry(),
	}
	g.cfg.Store(cfg)
	w := &webMux{g: g, ts: cfg.Join(), publicURL: "https://gateway.example.test", sessions: map[string]*oauthSession{}, onboard: g.onboard}
	w.routeAuth = routeAuthIndex(w.routes())
	return w
}

func openOnboardAuthTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := setDashboardUser(db, dashboardRootUsername, authTestRootPassword); err != nil {
		t.Fatalf("seed root password: %v", err)
	}
	return db
}

func newOnboardAuthTestWebMux(t *testing.T) *webMux {
	return newOnboardAuthTestWebMuxForControl(t, "wireguard")
}

func newOnboardAuthTestHandler(t *testing.T) http.Handler {
	return newOnboardAuthTestWebMux(t).handler()
}

func TestOnboardApproveRequiresDashboardPasswordInWireGuardMode(t *testing.T) {
	h := newOnboardAuthTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "dashboard session required") {
		t.Fatalf("body = %q, want dashboard password error", rr.Body.String())
	}
}

func TestOnboardApproveWithDashboardPasswordReachesHandlerInWireGuardMode(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	h := w.handler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.AddCookie(authTestSessionCookie(t, w))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown or expired code") {
		t.Fatalf("body = %q, want onboard handler error", rr.Body.String())
	}
}

func TestOnboardApproveWithDashboardPasswordMarksPendingSessionApprovedInWireGuardMode(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	h := w.handler()
	startReq := httptest.NewRequest(http.MethodPost, "/api/onboard/start?hostname=test-device&profile=default", nil)
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("start status = %d, want %d; body = %q", startRR.Code, http.StatusOK, startRR.Body.String())
	}
	var start struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(startRR.Body).Decode(&start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if start.UserCode == "" {
		t.Fatalf("start response missing user_code")
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(start.UserCode)+"&profile=default", nil)
	approveReq.AddCookie(authTestSessionCookie(t, w))
	approveRR := httptest.NewRecorder()
	h.ServeHTTP(approveRR, approveReq)
	if approveRR.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want %d; body = %q", approveRR.Code, http.StatusOK, approveRR.Body.String())
	}

	lookupReq := httptest.NewRequest(http.MethodGet, "/api/onboard/lookup?code="+url.QueryEscape(start.UserCode), nil)
	lookupRR := httptest.NewRecorder()
	h.ServeHTTP(lookupRR, lookupReq)
	if lookupRR.Code != http.StatusOK {
		t.Fatalf("lookup status = %d, want %d; body = %q", lookupRR.Code, http.StatusOK, lookupRR.Body.String())
	}
	var lookup struct {
		Approved bool `json:"approved"`
	}
	if err := json.NewDecoder(lookupRR.Body).Decode(&lookup); err != nil {
		t.Fatalf("decode lookup response: %v", err)
	}
	if !lookup.Approved {
		t.Fatalf("lookup approved = false, want true")
	}
}

func TestOnboardStartRemainsPublicWithDashboardPasswordInWireGuardMode(t *testing.T) {
	h := newOnboardAuthTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/start?hostname=test-device&profile=default", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "device_code") {
		t.Fatalf("body = %q, want onboarding start response", rr.Body.String())
	}
}

func TestRouteAuthRequirementsDocumentOnboardingBoundary(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	cases := []struct {
		path                string
		want                authRequirement
		wantDashboardPublic bool
		wantTailnetPublic   bool
	}{
		{path: "/api/onboard/start", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/api/onboard/poll", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/api/onboard/claim", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/api/onboard/lookup", want: authTailnetOperator, wantDashboardPublic: true, wantTailnetPublic: false},
		{path: "/api/onboard/approve", want: authDashboardOrTailnetOperator, wantDashboardPublic: false, wantTailnetPublic: false},
		{path: "/api/config", want: authDashboard, wantDashboardPublic: false, wantTailnetPublic: false},
		{path: "/api/env-pushdown", want: authSelfAuthenticating, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/api/hitl/operations/hitl_op_test/status", want: authSelfAuthenticating, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/info", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/ca.crt", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		// Login-page assets — the login page is authPublic and so are
		// the static resources it references; otherwise a logged-out
		// visit would chase the logo through the gate and render a
		// broken-image icon.
		{path: "/claw-patrol-logo.svg", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/claw-patrol-icon.svg", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/fonts/funnel-sans/FunnelSans-Variable--latin_basic.woff2", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := w.authRequirementForPath(tc.path); got != tc.want {
				t.Fatalf("auth requirement = %v, want %v", got, tc.want)
			}
			if got := w.skipsDashboardPassword(tc.path); got != tc.wantDashboardPublic {
				t.Fatalf("skipsDashboardPassword = %v, want %v", got, tc.wantDashboardPublic)
			}
			if got := w.skipsTailnetGate(tc.path); got != tc.wantTailnetPublic {
				t.Fatalf("skipsTailnetGate = %v, want %v", got, tc.wantTailnetPublic)
			}
		})
	}
}

func TestCredentialWebhookPrefixAuthPolicyIsSelfAuthenticating(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	path := credentialWebhookPrefix + "slack/interactive"
	if got := w.authRequirementForPath(path); got != authSelfAuthenticating {
		t.Fatalf("auth requirement = %v, want %v", got, authSelfAuthenticating)
	}
	if !w.skipsDashboardPassword(path) {
		t.Fatalf("credential webhook should not require dashboard password")
	}
	if !w.skipsTailnetGate(path) {
		t.Fatalf("credential webhook should skip tailnet gate: self-authenticating via HMAC, not Tailscale identity")
	}
}

func TestOnboardApproveRejectsProfileFallbackWithoutAuthenticatedPrincipal(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	s := w.onboard.start()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(s.userCode)+"&profile=default", nil)
	rr := httptest.NewRecorder()
	w.apiOnboardApprove(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if s.approved {
		t.Fatalf("session was approved using only profile fallback")
	}
}

func TestOnboardApproveUsesPrincipalAndTargetProfileSeparately(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	s := w.onboard.start()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(s.userCode)+"&profile=default", nil)
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardPassword, Owner: "dashboard"}))
	rr := httptest.NewRecorder()
	w.apiOnboardApprove(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !s.approved {
		t.Fatalf("session was not approved")
	}
	if s.profile != "default" {
		t.Fatalf("session profile = %q, want %q", s.profile, "default")
	}
}

func TestOnboardApproveWithDashboardPasswordInTailscaleModeDoesNotRequireTailnetPeer(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl(t, "tailscale")
	h := w.handler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.AddCookie(authTestSessionCookie(t, w))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown or expired code") {
		t.Fatalf("body = %q, want onboard handler error", rr.Body.String())
	}
}

// A tailnet operator whose login matches dashboard_operators can
// reach /api/onboard/approve without a dashboard password — that's
// the entire point of the operator allowlist. Reaching the handler
// shows up as a 404 because the code "NOPE" doesn't exist.
//
// Pre-#509 these tests didn't configure DashboardOperators at all
// and still expected the request to pass; that loose behavior let
// any tailnet member (including tag:client whois "tagged-devices")
// approve onboards. The fix requires an explicit allowlist match
// on operator-class routes; the test config now reflects that.
func TestOnboardApproveWithTailnetPrincipalInTailscaleModeReachesHandler(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl(t, "tailscale")
	w.g.cfg.Load().Settings.Tailscale.Operators = []string{"*@example.com"}
	h := w.handler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Tailscale-User-Login", "operator@example.com")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown or expired code") {
		t.Fatalf("body = %q, want onboard handler error", rr.Body.String())
	}
}

func TestOnboardApproveWithTailnetPrincipalInDefaultTailscaleModeReachesHandler(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl(t, "")
	w.g.cfg.Load().Settings.Tailscale.Operators = []string{"*@example.com"}
	h := w.handler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Tailscale-User-Login", "operator@example.com")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown or expired code") {
		t.Fatalf("body = %q, want onboard handler error", rr.Body.String())
	}
}

// Counterpart to the previous two tests: a tailnet identity that
// *doesn't* match dashboard_operators must be rejected on
// /api/onboard/approve even though Tailscale control mode is
// active. This is the #509 case — without this check, tag:client
// peers (whois resolves to "tagged-devices") could approve their
// own onboards.
func TestOnboardApproveRejectsTailnetPrincipalNotInOperators(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl(t, "tailscale")
	w.g.cfg.Load().Settings.Tailscale.Operators = []string{"*@example.com"}
	h := w.handler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	// "tagged-devices" is the tsnet whois reply for a tag:client
	// peer with no human identity attached.
	req.Header.Set("Tailscale-User-Login", "tagged-devices")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "operator routes require") {
		t.Fatalf("body = %q, want operator-gate error", rr.Body.String())
	}
}

// TestDashboardAuthGateFirstRunRedirect verifies that without a root
// row, every protected request redirects to /__login. This is the
// "credentials can never predate the password" invariant — if first-
// run is bypassed even once, downstream state may exist with no
// operator to protect it.
func TestDashboardAuthGateFirstRunRedirect(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Gateway{
		Settings: &config.GatewaySettings{
			WireGuard: &config.WireGuardBlock{SubnetCIDR: "10.55.0.0/24"},
		},
		Policy: &config.Policy{},
	}
	g := &Gateway{db: db, onboard: newOnboardRegistry()}
	g.cfg.Store(cfg)
	w := &webMux{g: g, ts: cfg.Join(), publicURL: "https://gateway.example.test", sessions: map[string]*oauthSession{}, onboard: g.onboard}
	h := w.handler()

	// API call: 401 with hint about set-dashboard-password.
	apiReq := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	apiRR := httptest.NewRecorder()
	h.ServeHTTP(apiRR, apiReq)
	if apiRR.Code != http.StatusUnauthorized {
		t.Fatalf("api status = %d, want %d; body = %q", apiRR.Code, http.StatusUnauthorized, apiRR.Body.String())
	}
	if !strings.Contains(apiRR.Body.String(), "set a password") && !strings.Contains(apiRR.Body.String(), "not initialized") {
		t.Fatalf("api body = %q, want first-run hint", apiRR.Body.String())
	}

	// Browser call: 302 to /__login.
	browserReq := httptest.NewRequest(http.MethodGet, "/", nil)
	browserRR := httptest.NewRecorder()
	h.ServeHTTP(browserRR, browserReq)
	if browserRR.Code != http.StatusFound {
		t.Fatalf("browser status = %d, want %d", browserRR.Code, http.StatusFound)
	}
	if loc := browserRR.Result().Header.Get("Location"); !strings.HasPrefix(loc, "/__login") {
		t.Fatalf("browser Location = %q, want /__login...", loc)
	}
}

// TestDashboardAuthGateAllowsTailnetOperatorWhenAllowlisted: with a
// configured dashboard_operators allowlist and tailscale-control
// mode, a request that lacks the password cookie but is whois-
// attributed to an allowlisted login should pass.
//
// We can't easily fake a real tsnet whois here, so we use the
// `Tailscale-User-Login` header trusted on loopback — equivalent
// effect for the gate's purposes.
func TestDashboardAuthGateAllowsTailnetOperatorWhenAllowlisted(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl(t, "tailscale")
	w.g.cfg.Load().Settings.Tailscale.Operators = []string{"alice@example.com", "*@example.org"}
	h := w.handler()

	cases := []struct {
		name  string
		login string
		want  int
	}{
		{name: "exact allowlist match", login: "alice@example.com", want: http.StatusOK},
		{name: "wildcard allowlist match", login: "bob@example.org", want: http.StatusOK},
		{name: "no match", login: "agent@nope.com", want: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Tailscale-User-Login", tc.login)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body = %q", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// TestDashboardAuthGateTailnetIdentityIgnoredInWireGuardMode: when
// only the `wireguard {}` block is enabled there is no tsnet whois
// identity, so a Tailscale-User-Login header (even one that would
// match an operator pattern) must NOT confer access. Password is
// still required.
func TestDashboardAuthGateTailnetIdentityIgnoredInWireGuardMode(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	h := w.handler()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Tailscale-User-Login", "alice@example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
}

// TestApplyDashboardPasswordFlagsSet covers --set-dashboard-password.
func TestApplyDashboardPasswordFlagsSet(t *testing.T) {
	db := openOnboardAuthTestDB(t)
	if err := deleteDashboardUser(db, dashboardRootUsername); err != nil {
		t.Fatalf("delete root: %v", err)
	}

	applyDashboardPasswordFlags(db, "cli-set-password-1234", false)

	if _, exists, _ := lookupDashboardUser(db, dashboardRootUsername); !exists {
		t.Fatal("root row should exist after --set-dashboard-password")
	}
	ok, _, err := checkDashboardPassword(db, dashboardRootUsername, "cli-set-password-1234")
	if err != nil {
		t.Fatalf("checkDashboardPassword: %v", err)
	}
	if !ok {
		t.Fatal("CLI-set password did not verify")
	}
}

// TestApplyDashboardPasswordFlagsReset covers --reset-dashboard-password.
func TestApplyDashboardPasswordFlagsReset(t *testing.T) {
	db := openOnboardAuthTestDB(t)

	applyDashboardPasswordFlags(db, "", true)

	if _, exists, _ := lookupDashboardUser(db, dashboardRootUsername); exists {
		t.Fatal("root row should be gone after --reset-dashboard-password")
	}
}

func TestHITLDecideRejectsProfileFallbackWithoutAuthenticatedPrincipal(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.hitl = newHITLRegistry(nil)
	id, ch := w.g.hitl.Add(runtime.HITLPending{Host: "api.example.test", Method: http.MethodPost, Path: "/v1/write"})

	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decide?profile=default", bytes.NewBufferString(`{"id":"`+id+`","allow":true}`))
	rr := httptest.NewRecorder()
	w.apiHITLDecide(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	select {
	case d := <-ch:
		t.Fatalf("decision was recorded using profile fallback: %+v", d)
	default:
	}
}

func TestHITLDecideRecordsAuthenticatedPrincipalNotTargetProfile(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.hitl = newHITLRegistry(nil)
	id, ch := w.g.hitl.Add(runtime.HITLPending{Host: "api.example.test", Method: http.MethodPost, Path: "/v1/write"})

	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decide?profile=default", bytes.NewBufferString(`{"id":"`+id+`","allow":true}`))
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardPassword, Owner: "operator@example.com"}))
	rr := httptest.NewRecorder()
	w.apiHITLDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusOK, rr.Body.String())
	}
	select {
	case d := <-ch:
		if !d.Allow {
			t.Fatalf("decision allow = false, want true")
		}
		if d.By != "operator@example.com" {
			t.Fatalf("decision by = %q, want authenticated principal", d.By)
		}
	default:
		t.Fatalf("no decision recorded")
	}
}
