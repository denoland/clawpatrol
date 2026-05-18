package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDashboardLoginRejectsProtocolRelativeNext(t *testing.T) {
	tests := []struct {
		name      string
		queryNext string
		want      string
	}{
		{
			name:      "valid dashboard path",
			queryNext: "/dashboard",
			want:      "/dashboard",
		},
		{
			name:      "protocol-relative URL",
			queryNext: "//evil.example/path",
			want:      "/",
		},
		{
			name:      "encoded protocol-relative URL",
			queryNext: "%2F%2Fevil.example%2Fpath",
			want:      "/",
		},
		{
			name:      "encoded backslash authority",
			queryNext: "%2F%5C%5Cevil.example%2Fpath",
			want:      "/",
		},
		{
			name:      "absolute URL",
			queryNext: "https%3A%2F%2Fevil.example%2Fpath",
			want:      "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &webMux{g: &Gateway{cfg: &config.Gateway{DashboardSecret: "s3cr3t"}}}
			r := httptest.NewRequest(http.MethodPost, "/__login?next="+tt.queryNext, strings.NewReader("secret=s3cr3t"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()

			w.apiDashboardLogin(rw, r)

			if rw.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", rw.Code, http.StatusFound)
			}
			if got := rw.Result().Header.Get("Location"); got != tt.want {
				t.Fatalf("Location = %q, want %q", got, tt.want)
			}
		})
	}
}
