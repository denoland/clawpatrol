package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

// newFingerprintWebMux wires a webMux against an in-memory CA so
// the fingerprint helpers have something to read. /info and
// /api/onboard/lookup are both authPublic / authTailnetOperator and
// skip the dashboard auth gate, so no root password is seeded — the
// dashboard's approval page must surface the fingerprint to the
// operator in WireGuard mode without any login wall.
func newFingerprintWebMux(t *testing.T) (*webMux, string) {
	t.Helper()
	cc, certPEM := inMemoryCertCache(t)
	cfg := &config.Gateway{
		Settings: &config.GatewaySettings{
			WireGuard: &config.WireGuardBlock{SubnetCIDR: "10.55.0.0/24"},
		},
		Policy: &config.Policy{},
	}
	g := &Gateway{
		certs:   cc,
		onboard: newOnboardRegistry(),
	}
	g.cfg.Store(cfg)
	w := &webMux{
		g:         g,
		ts:        cfg.Join(),
		publicURL: "https://gateway.example.test",
		sessions:  map[string]*oauthSession{},
		onboard:   g.onboard,
	}
	w.routeAuth = routeAuthIndex(w.routes())
	want, err := caFingerprintFromPEM(certPEM)
	if err != nil {
		t.Fatalf("caFingerprintFromPEM: %v", err)
	}
	return w, want
}

func TestInfoEndpointAdvertisesCAFingerprint(t *testing.T) {
	w, want := newFingerprintWebMux(t)
	rr := httptest.NewRecorder()
	w.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/info", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var body struct {
		CAFingerprint string `json:"ca_fingerprint"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.CAFingerprint != want {
		t.Fatalf("/info ca_fingerprint = %q, want %q", body.CAFingerprint, want)
	}
}

func TestOnboardLookupReturnsCAFingerprint(t *testing.T) {
	w, want := newFingerprintWebMux(t)
	s := w.onboard.start()
	rr := httptest.NewRecorder()
	w.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/onboard/lookup?code="+s.userCode, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var body struct {
		UserCode      string `json:"user_code"`
		CAFingerprint string `json:"ca_fingerprint"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.UserCode != s.userCode {
		t.Fatalf("user_code = %q, want %q", body.UserCode, s.userCode)
	}
	if body.CAFingerprint != want {
		t.Fatalf("ca_fingerprint = %q, want %q", body.CAFingerprint, want)
	}
}

// /api/onboard/lookup must stay reachable without dashboard auth in
// WireGuard mode — otherwise the operator hitting the approval link
// is redirected to a login wall and never sees the fingerprint we
// want them to compare against the CLI. Regression guard against a
// future tightening of the gate.
func TestOnboardLookupReachableInWireGuardModeWithoutDashboardAuth(t *testing.T) {
	w, _ := newFingerprintWebMux(t)
	s := w.onboard.start()
	rr := httptest.NewRecorder()
	w.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/onboard/lookup?code="+s.userCode, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "ca_fingerprint") {
		t.Fatalf("body %q missing ca_fingerprint", rr.Body.String())
	}
}
