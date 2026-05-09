package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

const authTestDashboardCredential = "test-dashboard-credential"

func newOnboardAuthTestHandler() http.Handler {
	return newOnboardAuthTestHandlerForControl("wireguard")
}

func newOnboardAuthTestHandlerForControl(control string) http.Handler {
	cfg := &config.Gateway{
		DashboardSecret: authTestDashboardCredential,
		Tailscale:       &config.Tailscale{Control: control},
		Policy:          &config.Policy{},
	}
	g := &Gateway{
		cfg:     cfg,
		onboard: newOnboardRegistry(),
	}
	return newWebMux(g, "", *cfg.Tailscale, "https://gateway.example.test")
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
	lookupReq.RemoteAddr = "127.0.0.1:12345"
	lookupReq.Header.Set("Tailscale-User-Login", "operator@example.test")
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

func TestOnboardApproveAllowsTailscaleServeCallerWithoutDashboardSecretInTailscaleMode(t *testing.T) {
	h := newOnboardAuthTestHandlerForControl("tailscale")
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
	approveReq.RemoteAddr = "127.0.0.1:12345"
	approveReq.Header.Set("Tailscale-User-Login", "operator@example.test")
	approveRR := httptest.NewRecorder()
	h.ServeHTTP(approveRR, approveReq)
	if approveRR.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want %d; body = %q", approveRR.Code, http.StatusOK, approveRR.Body.String())
	}

	lookupReq := httptest.NewRequest(http.MethodGet, "/api/onboard/lookup?code="+url.QueryEscape(start.UserCode), nil)
	lookupReq.RemoteAddr = "127.0.0.1:12345"
	lookupReq.Header.Set("Tailscale-User-Login", "operator@example.test")
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

func TestOnboardApproveRequiresTailnetCallerEvenWithDashboardSecretInTailscaleMode(t *testing.T) {
	h := newOnboardAuthTestHandlerForControl("tailscale")
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Clawpatrol-Secret", authTestDashboardCredential)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "tailnet access required") {
		t.Fatalf("body = %q, want tailnet access error", rr.Body.String())
	}
}
