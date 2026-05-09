package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestTailnetGateAllowsEnvPushdownToReachBearerAuth(t *testing.T) {
	w := &webMux{g: &Gateway{cfg: &config.Gateway{Tailscale: &config.Tailscale{Control: "tailscale"}}}}
	reached := false
	h := w.tailnetGate(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		reached = true
		http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/env-pushdown", nil)
	r.RemoteAddr = "203.0.113.10:12345"
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)

	if !reached {
		t.Fatal("/api/env-pushdown was blocked by tailnetGate before bearer auth")
	}
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d from bearer auth handler", rw.Code, http.StatusUnauthorized)
	}
}
