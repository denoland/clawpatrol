package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

const authTestDashboardCredential = "test-dashboard-credential"

func newOnboardAuthTestWebMuxForControl(control string) *webMux {
	cfg := &config.Gateway{
		DashboardSecret: authTestDashboardCredential,
		Control:         control,
		Policy:          &config.Policy{},
	}
	g := &Gateway{
		cfg:     cfg,
		onboard: newOnboardRegistry(),
	}
	w := &webMux{g: g, ts: cfg.Join(), publicURL: "https://gateway.example.test", sessions: map[string]*oauthSession{}, onboard: g.onboard, previews: map[string]configPreviewToken{}}
	w.routeAuth = routeAuthIndex(w.routes())
	return w
}

func newOnboardAuthTestWebMux() *webMux {
	return newOnboardAuthTestWebMuxForControl("wireguard")
}

func newOnboardAuthTestHandler() http.Handler {
	w := newOnboardAuthTestWebMux()
	return w.handler()
}

func TestOnboardApproveRequiresDashboardSecretInWireGuardMode(t *testing.T) {
	h := newOnboardAuthTestHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "dashboard secret required") {
		t.Fatalf("body = %q, want dashboard secret error", rr.Body.String())
	}
}

func TestOnboardApproveWithDashboardSecretReachesHandlerInWireGuardMode(t *testing.T) {
	h := newOnboardAuthTestHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.Header.Set("X-Clawpatrol-Secret", authTestDashboardCredential)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown or expired code") {
		t.Fatalf("body = %q, want onboard handler error", rr.Body.String())
	}
}

func TestOnboardApproveWithDashboardSecretMarksPendingSessionApprovedInWireGuardMode(t *testing.T) {
	h := newOnboardAuthTestHandler()
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
	approveReq.Header.Set("X-Clawpatrol-Secret", authTestDashboardCredential)
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

func TestOnboardStartRemainsPublicWithDashboardSecretInWireGuardMode(t *testing.T) {
	h := newOnboardAuthTestHandler()
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
	w := newOnboardAuthTestWebMux()
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
		{path: "/api/config/save", want: authDashboard, wantDashboardPublic: false, wantTailnetPublic: false},
		{path: "/api/env-pushdown", want: authSelfAuthenticating, wantDashboardPublic: true, wantTailnetPublic: false},
		{path: "/info", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
		{path: "/ca.crt", want: authPublic, wantDashboardPublic: true, wantTailnetPublic: true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := w.authRequirementForPath(tc.path); got != tc.want {
				t.Fatalf("auth requirement = %v, want %v", got, tc.want)
			}
			if got := w.skipsDashboardSecret(tc.path); got != tc.wantDashboardPublic {
				t.Fatalf("skipsDashboardSecret = %v, want %v", got, tc.wantDashboardPublic)
			}
			if got := w.skipsTailnetGate(tc.path); got != tc.wantTailnetPublic {
				t.Fatalf("skipsTailnetGate = %v, want %v", got, tc.wantTailnetPublic)
			}
		})
	}
}

func TestCredentialWebhookPrefixAuthPolicyIsSelfAuthenticating(t *testing.T) {
	w := newOnboardAuthTestWebMux()
	path := credentialWebhookPrefix + "slack/interactive"
	if got := w.authRequirementForPath(path); got != authSelfAuthenticating {
		t.Fatalf("auth requirement = %v, want %v", got, authSelfAuthenticating)
	}
	if !w.skipsDashboardSecret(path) {
		t.Fatalf("credential webhook should not require dashboard secret")
	}
	if w.skipsTailnetGate(path) {
		t.Fatalf("credential webhook tailnet behavior should remain gated in tailscale mode")
	}
}

func TestOnboardApproveRejectsProfileFallbackWithoutAuthenticatedPrincipal(t *testing.T) {
	w := newOnboardAuthTestWebMux()
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
	w := newOnboardAuthTestWebMux()
	s := w.onboard.start()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(s.userCode)+"&profile=default", nil)
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardSecret, Owner: "dashboard"}))
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

func TestOnboardApproveWithDashboardSecretInTailscaleModeDoesNotRequireTailnetPeer(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl("tailscale")
	h := w.handler()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.Header.Set("X-Clawpatrol-Secret", authTestDashboardCredential)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown or expired code") {
		t.Fatalf("body = %q, want onboard handler error", rr.Body.String())
	}
}

func TestOnboardApproveWithTailnetPrincipalInTailscaleModeDoesNotRequireDashboardSecret(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl("tailscale")
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

func TestOnboardApproveWithTailnetPrincipalInDefaultTailscaleModeDoesNotRequireDashboardSecret(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl("")
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

func TestHITLDecideRejectsProfileFallbackWithoutAuthenticatedPrincipal(t *testing.T) {
	w := newOnboardAuthTestWebMux()
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
	w := newOnboardAuthTestWebMux()
	w.g.hitl = newHITLRegistry(nil)
	id, ch := w.g.hitl.Add(runtime.HITLPending{Host: "api.example.test", Method: http.MethodPost, Path: "/v1/write"})

	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decide?profile=default", bytes.NewBufferString(`{"id":"`+id+`","allow":true}`))
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardSecret, Owner: "operator@example.com"}))
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
