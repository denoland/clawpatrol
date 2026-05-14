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

// newProfileValidationWebMux builds a webMux with a small declared
// policy ("default", "staging") for the profile-validation tests.
// Re-uses the onboard auth helpers' shape so the auth gates behave
// identically and the only variable under test is profile validation.
func newProfileValidationWebMux() *webMux {
	cfg := &config.Gateway{
		DashboardSecret: authTestDashboardCredential,
		Control:         "wireguard",
		Policy: &config.Policy{
			Profiles: map[string]*config.Profile{
				"default": {Name: "default"},
				"staging": {Name: "staging"},
			},
			Order: []string{"default", "staging"},
		},
	}
	g := &Gateway{cfg: cfg, onboard: newOnboardRegistry()}
	w := &webMux{
		g:         g,
		ts:        cfg.Join(),
		publicURL: "https://gateway.example.test",
		sessions:  map[string]*oauthSession{},
		onboard:   g.onboard,
		previews:  map[string]configPreviewToken{},
	}
	w.routeAuth = routeAuthIndex(w.routes())
	return w
}

func TestProfileExistsRecognizesDeclaredProfile(t *testing.T) {
	p := &config.Policy{
		Profiles: map[string]*config.Profile{
			"prod": {Name: "prod"},
		},
	}
	if !profileExists(p, "prod") {
		t.Fatalf("profileExists(prod) = false, want true")
	}
	if profileExists(p, "staging") {
		t.Fatalf("profileExists(staging) = true, want false")
	}
	if profileExists(p, "") {
		t.Fatalf("profileExists(\"\") = true, want false")
	}
	if profileExists(nil, "prod") {
		t.Fatalf("profileExists(nil, prod) = true, want false")
	}
}

func TestOnboardStartAcceptsDeclaredProfile(t *testing.T) {
	w := newProfileValidationWebMux()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/start?hostname=h&profile=staging", nil)
	rr := httptest.NewRecorder()
	w.apiOnboardStart(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var resp struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	s := w.onboard.byUserCode(resp.UserCode)
	if s == nil {
		t.Fatalf("session not found for user_code %q", resp.UserCode)
	}
	if s.profile != "staging" {
		t.Fatalf("session profile = %q, want %q", s.profile, "staging")
	}
}

func TestOnboardStartRejectsUnknownProfile(t *testing.T) {
	w := newProfileValidationWebMux()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/start?hostname=h&profile=typo", nil)
	rr := httptest.NewRecorder()
	w.apiOnboardStart(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown profile") {
		t.Fatalf("body = %q, want unknown-profile error", rr.Body.String())
	}
	// The rejection must happen before the session is allocated; we
	// can't address the session by user_code (the response had none),
	// but we can prove no session was registered at all.
	w.onboard.mu.Lock()
	count := len(w.onboard.byUser)
	w.onboard.mu.Unlock()
	if count != 0 {
		t.Fatalf("byUser size = %d, want 0 (unknown profile must not allocate a session)", count)
	}
}

func TestOnboardStartAcceptsMissingProfile(t *testing.T) {
	w := newProfileValidationWebMux()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/start?hostname=h", nil)
	rr := httptest.NewRecorder()
	w.apiOnboardStart(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var resp struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	s := w.onboard.byUserCode(resp.UserCode)
	if s == nil {
		t.Fatalf("session not found")
	}
	if s.profile != "" {
		t.Fatalf("session profile = %q, want empty (no suggestion)", s.profile)
	}
}

func TestOnboardApproveRejectsUnknownProfileQueryParam(t *testing.T) {
	w := newProfileValidationWebMux()
	s := w.onboard.start()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(s.userCode)+"&profile=typo", nil)
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardSecret, Owner: "dashboard"}))
	rr := httptest.NewRecorder()
	w.apiOnboardApprove(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown profile") {
		t.Fatalf("body = %q, want unknown-profile error", rr.Body.String())
	}
	if s.approved {
		t.Fatalf("session approved despite invalid profile (key minting must not run)")
	}
	if s.profile != "" {
		t.Fatalf("session.profile = %q, want empty (rejected before assignment)", s.profile)
	}
}

func TestOnboardApproveUsesCliSuggestionWhenDashboardSendsNone(t *testing.T) {
	w := newProfileValidationWebMux()
	// Simulate `clawpatrol join --profile staging` having already
	// hit /start: stash the suggestion on the session directly so
	// this test stays focused on approve-time priority.
	s := w.onboard.start()
	w.onboard.mu.Lock()
	s.profile = "staging"
	w.onboard.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(s.userCode), nil)
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardSecret, Owner: "dashboard"}))
	rr := httptest.NewRecorder()
	w.apiOnboardApprove(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	if s.profile != "staging" {
		t.Fatalf("session profile = %q, want %q (CLI suggestion should win when dashboard sends no override)", s.profile, "staging")
	}
}

func TestOnboardApproveRejectsStaleSessionSuggestionAfterPolicyReload(t *testing.T) {
	w := newProfileValidationWebMux()
	// Simulate the policy reload race: the CLI suggested "ghost" and
	// /start accepted it because the policy declared it at the time;
	// then the operator removed "ghost" from gateway.hcl before
	// clicking approve. Approve must reject rather than silently
	// fall back to defaults — the operator's intent is ambiguous.
	s := w.onboard.start()
	w.onboard.mu.Lock()
	s.profile = "ghost"
	w.onboard.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(s.userCode), nil)
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardSecret, Owner: "dashboard"}))
	rr := httptest.NewRecorder()
	w.apiOnboardApprove(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rr.Code, rr.Body.String())
	}
	if s.approved {
		t.Fatalf("session approved with stale CLI suggestion")
	}
}

func TestOnboardApproveFallsBackToDefaultWhenNoProfileSpecified(t *testing.T) {
	w := newProfileValidationWebMux()
	s := w.onboard.start()

	req := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(s.userCode), nil)
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardSecret, Owner: "dashboard"}))
	rr := httptest.NewRecorder()
	w.apiOnboardApprove(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	if s.profile != "default" {
		t.Fatalf("session profile = %q, want %q (no-profile fallback)", s.profile, "default")
	}
}

func TestOnboardLookupSurfacesHostnameAndSuggestedProfile(t *testing.T) {
	w := newProfileValidationWebMux()

	startReq := httptest.NewRequest(http.MethodPost, "/api/onboard/start?hostname=magurobot&profile=staging", nil)
	startRR := httptest.NewRecorder()
	w.apiOnboardStart(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("start status = %d, want 200; body = %q", startRR.Code, startRR.Body.String())
	}
	var start struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(startRR.Body).Decode(&start); err != nil {
		t.Fatalf("decode start: %v", err)
	}

	lookupReq := httptest.NewRequest(http.MethodGet, "/api/onboard/lookup?code="+url.QueryEscape(start.UserCode), nil)
	lookupRR := httptest.NewRecorder()
	w.apiOnboardLookup(lookupRR, lookupReq)
	if lookupRR.Code != http.StatusOK {
		t.Fatalf("lookup status = %d, want 200; body = %q", lookupRR.Code, lookupRR.Body.String())
	}
	var lookup struct {
		Hostname         string `json:"hostname"`
		SuggestedProfile string `json:"suggested_profile"`
	}
	if err := json.NewDecoder(lookupRR.Body).Decode(&lookup); err != nil {
		t.Fatalf("decode lookup: %v", err)
	}
	if lookup.Hostname != "magurobot" {
		t.Fatalf("hostname = %q, want %q", lookup.Hostname, "magurobot")
	}
	if lookup.SuggestedProfile != "staging" {
		t.Fatalf("suggested_profile = %q, want %q", lookup.SuggestedProfile, "staging")
	}
}
