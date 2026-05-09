package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestDashboardSecretQueryParamIsNotAccepted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/state?secret=s3cr3t", nil)
	if checkDashboardSecret(r, "s3cr3t") {
		t.Fatal("dashboard secret in query string was accepted")
	}

	r = httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.Header.Set("X-Clawpatrol-Secret", "s3cr3t")
	if !checkDashboardSecret(r, "s3cr3t") {
		t.Fatal("dashboard secret header was rejected")
	}
}

func TestDashboardLoginGetDoesNotAcceptSecretQueryParam(t *testing.T) {
	w := &webMux{g: &Gateway{cfg: &config.Gateway{DashboardSecret: "s3cr3t"}}}
	r := httptest.NewRequest(http.MethodGet, "/__login?secret=s3cr3t&next=/api/state", nil)
	rw := httptest.NewRecorder()

	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusOK)
	}
	if cookies := rw.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("GET /__login?secret=... set cookies: %+v", cookies)
	}
}
