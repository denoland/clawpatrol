package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// claimForTest drives start → approve → claim and returns the decoded
// claim response body. Status is asserted 200 by the caller's contract:
// a claim that resolves an owner succeeds even when token minting does
// not, which is exactly the case these tests pin down.
//
// beforeClaim (optional) runs after approval and before the claim, so a
// test can break minting without also breaking approve — which needs
// the db for its dashboard session.
func claimForTest(t *testing.T, w *webMux, ip string, beforeClaim func()) map[string]string {
	t.Helper()
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
	if beforeClaim != nil {
		beforeClaim()
	}
	claimReq := httptest.NewRequest(http.MethodPost,
		"/api/onboard/claim?device_code="+url.QueryEscape(dc)+"&ip="+url.QueryEscape(ip)+"&hostname=dev1", nil)
	claimRR := httptest.NewRecorder()
	h.ServeHTTP(claimRR, claimReq)
	if claimRR.Code != http.StatusOK {
		t.Fatalf("claim status = %d; body = %q", claimRR.Code, claimRR.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(claimRR.Body).Decode(&resp); err != nil {
		t.Fatalf("decode claim response: %v", err)
	}
	return resp
}

// A healthy claim mints the per-peer bearer. In Tailscale mode this is
// the only place it's minted, so `clawpatrol join` has nothing to
// persist as ~/.clawpatrol/api-token without it.
func TestOnboardClaimMintsAPIToken(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.agents = NewAgentRegistry()
	w.g.agents.onboard = w.g.onboard

	resp := claimForTest(t, w, "100.64.0.9", nil)

	if resp["api_token"] == "" {
		t.Fatalf("claim response missing api_token: %v", resp)
	}
	if got := resp["api_token_error"]; got != "" {
		t.Errorf("api_token_error = %q, want empty on the success path", got)
	}
	if ip := peerIPForAPIToken(w.g.db, resp["api_token"]); ip != "100.64.0.9" {
		t.Errorf("peerIPForAPIToken = %q, want 100.64.0.9 (token must be persisted)", ip)
	}
}

// Regression: a mint failure used to be swallowed — the claim returned
// 200 with no api_token and no explanation, and the operator only found
// out much later via the daemon's "peer api token not persisted",
// with no way to tell a token-less gateway from a broken database.
// The reason must travel back to the CLI.
func TestOnboardClaimSurfacesMintFailure(t *testing.T) {
	w := newOnboardAuthTestWebMux(t)
	w.g.agents = NewAgentRegistry()
	w.g.agents.onboard = w.g.onboard

	// Cheapest deterministic mint failure: mintAndPersistPeerAPIToken
	// rejects a nil db before it touches rand or sqlite. Drop it only
	// after approve, which needs the db for its dashboard session.
	resp := claimForTest(t, w, "100.64.0.10", func() { w.g.db = nil })

	if tok := resp["api_token"]; tok != "" {
		t.Fatalf("api_token = %q, want empty when minting fails", tok)
	}
	if resp["api_token_error"] == "" {
		t.Fatalf("claim response must explain why minting failed: %v", resp)
	}
	// The claim itself still did its job: the IP is bound to the owner.
	if resp["ip"] != "100.64.0.10" || resp["owner"] == "" {
		t.Errorf("claim response = %v, want owner+ip still populated", resp)
	}
}
