package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestDashboardLoginCookieDoesNotStoreRawSecret(t *testing.T) {
	const secret = "s3cr3t"
	w := &webMux{g: &Gateway{cfg: &config.Gateway{DashboardSecret: secret}}}
	form := url.Values{"secret": {secret}}
	r := httptest.NewRequest(http.MethodPost, "/__login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	w.apiDashboardLogin(rw, r)

	var dashCookie *http.Cookie
	for _, c := range rw.Result().Cookies() {
		if c.Name == "cp_dash" {
			dashCookie = c
		}
	}
	if dashCookie == nil {
		t.Fatal("login did not set cp_dash cookie")
	}
	if dashCookie.Value == secret {
		t.Fatal("cp_dash cookie stored the raw dashboard secret")
	}

	authReq := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	authReq.AddCookie(dashCookie)
	if !checkDashboardSecret(authReq, secret) {
		t.Fatal("derived dashboard cookie was rejected")
	}
}

func TestRawDashboardSecretCookieIsRejected(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.AddCookie(&http.Cookie{Name: "cp_dash", Value: "s3cr3t"})
	if checkDashboardSecret(r, "s3cr3t") {
		t.Fatal("raw dashboard secret cookie was accepted")
	}
}
