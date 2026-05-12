package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestLoadOrCreateAdminTokenGeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	tok, created, err := loadOrCreateAdminToken(dir)
	if err != nil {
		t.Fatalf("loadOrCreateAdminToken: %v", err)
	}
	if !created {
		t.Fatalf("created = false on first call")
	}
	if len(tok) < 20 {
		t.Fatalf("token too short: %q", tok)
	}
	info, err := os.Stat(adminTokenPath(dir))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o, want 0600", perm)
	}
}

func TestLoadOrCreateAdminTokenIsStableAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	first, _, err := loadOrCreateAdminToken(dir)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, created, err := loadOrCreateAdminToken(dir)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if created {
		t.Fatalf("created = true on second call; want false")
	}
	if first != second {
		t.Fatalf("tokens differ between calls: %q vs %q", first, second)
	}
}

func TestLoadAdminTokenAbsentReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	tok, err := loadAdminToken(dir)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if tok != "" {
		t.Fatalf("tok = %q, want empty", tok)
	}
}

func TestLoadAdminTokenTrimsTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(adminTokenPath(dir), []byte("the-token\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	tok, err := loadAdminToken(dir)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if tok != "the-token" {
		t.Fatalf("tok = %q, want %q", tok, "the-token")
	}
}

func TestResolveStateDirFallsBackToCADirRelative(t *testing.T) {
	cfg := &config.Gateway{CADir: "/opt/clawpatrol/ca"}
	got := resolveStateDir(cfg)
	want := filepath.Join("/opt/clawpatrol/ca", "..", "oauth")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveStateDirPrefersOAuthDir(t *testing.T) {
	cfg := &config.Gateway{OAuthDir: "/var/lib/clawpatrol", CADir: "/opt/clawpatrol/ca"}
	if got := resolveStateDir(cfg); got != "/var/lib/clawpatrol" {
		t.Fatalf("got %q, want /var/lib/clawpatrol", got)
	}
}

// adminTokenGateTestMux returns a webMux configured with the supplied
// HCL dashboard_secret + persisted admin token. Either may be empty.
func adminTokenGateTestMux(dashboardSecret, adminToken string) *webMux {
	cfg := &config.Gateway{
		DashboardSecret: dashboardSecret,
		Control:         "wireguard",
		Policy:          &config.Policy{},
	}
	g := &Gateway{cfg: cfg, onboard: newOnboardRegistry()}
	if adminToken != "" {
		g.setAdminToken(adminToken)
	}
	w := &webMux{
		g:        g,
		caDir:    "",
		ts:       cfg.Join(),
		sessions: map[string]*oauthSession{},
		onboard:  g.onboard,
		previews: map[string]configPreviewToken{},
	}
	w.routeAuth = routeAuthIndex(w.routes())
	return w
}

func TestDashboardSecretGateAcceptsPersistedAdminToken(t *testing.T) {
	w := adminTokenGateTestMux("", "persisted-admin-token")
	h := w.handler()

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("X-Clawpatrol-Secret", "persisted-admin-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusServiceUnavailable {
		t.Fatalf("admin token rejected: status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestDashboardSecretGateAcceptsEitherTokenWhenBothSet(t *testing.T) {
	w := adminTokenGateTestMux("hcl-secret", "admin-token")
	h := w.handler()

	for name, value := range map[string]string{
		"hcl":   "hcl-secret",
		"admin": "admin-token",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
			req.Header.Set("X-Clawpatrol-Secret", value)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code == http.StatusUnauthorized {
				t.Fatalf("token %q rejected", value)
			}
		})
	}
}

func TestDashboardSecretGateRejectsUnknownToken(t *testing.T) {
	w := adminTokenGateTestMux("hcl-secret", "admin-token")
	h := w.handler()

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("X-Clawpatrol-Secret", "nope")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestDashboardSecretGateMisconfiguredWhenNoTokenAndNoOptOut(t *testing.T) {
	w := adminTokenGateTestMux("", "")
	h := w.handler()

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d (misconfigured)", rr.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rr.Body.String(), "dashboard refuses to serve") {
		t.Fatalf("body = %q, want misconfig message", rr.Body.String())
	}
}

func TestCheckDashboardCredentialEmptyTokensRejects(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Clawpatrol-Secret", "anything")
	if checkDashboardCredential(req, nil) {
		t.Fatalf("nil tokens accepted a request")
	}
	if checkDashboardCredential(req, []string{""}) {
		t.Fatalf("empty-string token accepted a request")
	}
}
