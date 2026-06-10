package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

// onboardProfileTestPolicy returns a policy with two profiles and no
// profile literally named "default", so the fallback is the first
// profile in source order ("staging").
func onboardProfileTestPolicy() *config.Policy {
	return &config.Policy{
		Profiles: map[string]*config.Profile{
			"staging": {Name: "staging"},
			"prod":    {Name: "prod"},
		},
		Order: []string{"staging", "prod"},
	}
}

func startOnboardSession(t *testing.T, h http.Handler, startQuery string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/onboard/start"+startQuery, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start status = %d; body = %q", rr.Code, rr.Body.String())
	}
	var start struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if start.UserCode == "" {
		t.Fatalf("start response missing user_code")
	}
	return start.UserCode
}

func TestOnboardLookupIncludesProfilesAndSuggestion(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.cfg.Load().Policy = onboardProfileTestPolicy()
	h := w.handler()

	for _, tc := range []struct {
		startQuery    string
		wantSuggested string
	}{
		{"?hostname=dev1&profile=prod", "prod"},
		{"?hostname=dev2", "staging"},                     // no suggestion → first profile
		{"?hostname=dev3&profile=nonexistent", "staging"}, // bogus suggestion → fallback
	} {
		code := startOnboardSession(t, h, tc.startQuery)
		req := httptest.NewRequest(http.MethodGet, "/api/onboard/lookup?code="+url.QueryEscape(code), nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("lookup(%s) status = %d; body = %q", tc.startQuery, rr.Code, rr.Body.String())
		}
		var lookup struct {
			Profiles  []string `json:"profiles"`
			Suggested string   `json:"suggested_profile"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&lookup); err != nil {
			t.Fatalf("decode lookup response: %v", err)
		}
		if len(lookup.Profiles) != 2 || lookup.Profiles[0] != "staging" || lookup.Profiles[1] != "prod" {
			t.Errorf("lookup(%s) profiles = %v, want [staging prod]", tc.startQuery, lookup.Profiles)
		}
		if lookup.Suggested != tc.wantSuggested {
			t.Errorf("lookup(%s) suggested_profile = %q, want %q", tc.startQuery, lookup.Suggested, tc.wantSuggested)
		}
	}
}

func TestOnboardApproveRejectsUnknownProfile(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.cfg.Load().Policy = onboardProfileTestPolicy()
	h := w.handler()
	code := startOnboardSession(t, h, "?hostname=dev1")

	req := httptest.NewRequest(http.MethodPost,
		"/api/onboard/approve?code="+url.QueryEscape(code)+"&profile=nonexistent", nil)
	req.AddCookie(authTestSessionCookie(t, w))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("approve status = %d, want 400; body = %q", rr.Code, rr.Body.String())
	}
}

func TestOnboardApproveResolvesAndReportsProfile(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.cfg.Load().Policy = onboardProfileTestPolicy()
	h := w.handler()

	for _, tc := range []struct {
		startQuery   string
		approveQuery string
		want         string
	}{
		{"?hostname=dev1&profile=prod", "", "prod"},                    // CLI suggestion honored
		{"?hostname=dev2&profile=prod", "&profile=staging", "staging"}, // operator override wins
		{"?hostname=dev3", "", "staging"},                              // nothing specified → fallback
	} {
		code := startOnboardSession(t, h, tc.startQuery)
		req := httptest.NewRequest(http.MethodPost,
			"/api/onboard/approve?code="+url.QueryEscape(code)+tc.approveQuery, nil)
		req.AddCookie(authTestSessionCookie(t, w))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("approve(%s%s) status = %d; body = %q", tc.startQuery, tc.approveQuery, rr.Code, rr.Body.String())
		}
		var resp struct {
			Approved bool   `json:"approved"`
			Profile  string `json:"profile"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode approve response: %v", err)
		}
		if !resp.Approved || resp.Profile != tc.want {
			t.Errorf("approve(%s%s) = %+v, want approved with profile %q", tc.startQuery, tc.approveQuery, resp, tc.want)
		}
	}
}

// A claim must make the device visible on the dashboard immediately,
// before any traffic flows.
func TestOnboardClaimSeedsAgentsRegistry(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.cfg.Load().Policy = onboardProfileTestPolicy()
	w.g.agents = NewAgentRegistry()
	w.g.agents.onboard = w.g.onboard
	h := w.handler()
	code := startOnboardSession(t, h, "?hostname=dev1")

	approveReq := httptest.NewRequest(http.MethodPost, "/api/onboard/approve?code="+url.QueryEscape(code), nil)
	approveReq.AddCookie(authTestSessionCookie(t, w))
	approveRR := httptest.NewRecorder()
	h.ServeHTTP(approveRR, approveReq)
	if approveRR.Code != http.StatusOK {
		t.Fatalf("approve status = %d; body = %q", approveRR.Code, approveRR.Body.String())
	}

	dc := w.onboard.byUserCode(code).deviceCode
	claimReq := httptest.NewRequest(http.MethodPost,
		"/api/onboard/claim?device_code="+url.QueryEscape(dc)+"&ip=10.55.0.9&hostname=dev1", nil)
	claimRR := httptest.NewRecorder()
	h.ServeHTTP(claimRR, claimReq)
	if claimRR.Code != http.StatusOK {
		t.Fatalf("claim status = %d; body = %q", claimRR.Code, claimRR.Body.String())
	}

	for _, a := range w.g.agents.snapshot() {
		if a.IP == "10.55.0.9" {
			return
		}
	}
	t.Fatalf("agents registry has no entry for 10.55.0.9 after claim")
}

// The tsnet placeholder seeded at approve time must be promoted to
// the real tailnet IP on the daemon's first register call: agents
// entry replaced, profile and hostname carried over, devices row
// created.
func TestTsnetRegisterPromotesSeededPlaceholder(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl(t, "tailscale")
	w.g.cfg.Load().Policy = onboardProfileTestPolicy()
	w.g.agents = NewAgentRegistry()
	w.g.agents.onboard = w.g.onboard
	if err := w.g.onboard.Load(w.g.db); err != nil {
		t.Fatalf("onboard load: %v", err)
	}
	h := w.handler()

	const placeholder = tsnetPlaceholderPrefix + "myhost"
	w.g.onboard.seedPlaceholder(placeholder, "myhost", "op@example.com", "prod")
	w.g.agents.Seed(placeholder)

	var seeded *Agent
	for _, a := range w.g.agents.snapshot() {
		if a.IP == placeholder {
			seeded = a
		}
	}
	if seeded == nil {
		t.Fatalf("placeholder %q not in agents registry after Seed", placeholder)
	}
	if seeded.Hostname != "myhost" || seeded.User != "op@example.com" || seeded.Profile != "prod" {
		t.Fatalf("seeded placeholder = hostname %q user %q profile %q, want myhost/op@example.com/prod",
			seeded.Hostname, seeded.User, seeded.Profile)
	}

	token, err := mintAndPersistPeerAPIToken(w.g.db, placeholder)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/peer/tsnet/register?ip=100.64.0.7&hostname=myhost", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("register status = %d, want 204; body = %q", rr.Code, rr.Body.String())
	}

	var promoted *Agent
	for _, a := range w.g.agents.snapshot() {
		if a.IP == placeholder {
			t.Errorf("placeholder %q still in agents registry after register", placeholder)
		}
		if a.IP == "100.64.0.7" {
			promoted = a
		}
	}
	if promoted == nil {
		t.Fatalf("registered IP 100.64.0.7 not in agents registry")
	}
	if got := w.g.onboard.ProfileForIP("100.64.0.7"); got != "prod" {
		t.Errorf("ProfileForIP(100.64.0.7) = %q, want prod", got)
	}
	if got := w.g.onboard.HostnameForIP("100.64.0.7"); got != "myhost" {
		t.Errorf("HostnameForIP(100.64.0.7) = %q, want myhost", got)
	}
	if got := w.g.onboard.OwnerForIP("100.64.0.7"); got != "op@example.com" {
		t.Errorf("OwnerForIP(100.64.0.7) = %q, want op@example.com (owner must carry across promotion)", got)
	}
	if !w.g.onboard.HasDevice("100.64.0.7") {
		t.Errorf("devices row for 100.64.0.7 missing after register promotion")
	}
}
