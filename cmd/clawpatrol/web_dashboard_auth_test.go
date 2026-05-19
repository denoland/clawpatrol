package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

// newDashboardTestMux opens a fresh in-temp-dir DB, optionally seeds
// the root password row, and returns a webMux wired to it. Tests use
// this instead of building a partial Gateway by hand — the gate
// reads from the DB, so a real (if temporary) DB is required.
func newDashboardTestMux(t *testing.T, cfg *config.Gateway, rootPassword string) *webMux {
	t.Helper()
	if cfg == nil {
		cfg = &config.Gateway{}
	}
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if rootPassword != "" {
		if err := setDashboardUser(db, dashboardRootUsername, rootPassword); err != nil {
			t.Fatalf("seed root password: %v", err)
		}
	}
	return &webMux{g: &Gateway{cfg: cfg, db: db}}
}

func TestCheckDashboardPasswordRejectsQueryParam(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/api/state?password=correct-horse-battery-staple", nil)
	if ok, _, _ := w.checkDashboardPasswordRequest(r); ok {
		t.Fatal("password in query string was accepted")
	}
}

func TestCheckDashboardPasswordAcceptsHeader(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.Header.Set("X-Clawpatrol-Secret", "correct-horse-battery-staple")
	ok, _, err := w.checkDashboardPasswordRequest(r)
	if err != nil {
		t.Fatalf("checkDashboardPasswordRequest: %v", err)
	}
	if !ok {
		t.Fatal("X-Clawpatrol-Secret header was rejected")
	}
}

func TestCheckDashboardPasswordAcceptsCookie(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.AddCookie(&http.Cookie{Name: cpDashCookieName, Value: "correct-horse-battery-staple"})
	ok, _, err := w.checkDashboardPasswordRequest(r)
	if err != nil {
		t.Fatalf("checkDashboardPasswordRequest: %v", err)
	}
	if !ok {
		t.Fatal("cp_dash cookie was rejected")
	}
}

func TestCheckDashboardPasswordRejectsWrongPassword(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.AddCookie(&http.Cookie{Name: cpDashCookieName, Value: "wrong-password"})
	if ok, _, _ := w.checkDashboardPasswordRequest(r); ok {
		t.Fatal("wrong password was accepted")
	}
}

func TestDashboardLoginGetDoesNotAcceptPasswordQueryParam(t *testing.T) {
	w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")

	r := httptest.NewRequest(http.MethodGet, "/__login?password=correct-horse-battery-staple&next=/api/state", nil)
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusOK)
	}
	if cookies := rw.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("GET /__login?password=... set cookies: %+v", cookies)
	}
}

func TestDashboardLoginRejectsProtocolRelativeNext(t *testing.T) {
	tests := []struct {
		name      string
		queryNext string
		want      string
	}{
		{name: "valid dashboard path", queryNext: "/dashboard", want: "/dashboard"},
		{name: "protocol-relative URL", queryNext: "//evil.example/path", want: "/"},
		{name: "encoded protocol-relative URL", queryNext: "%2F%2Fevil.example%2Fpath", want: "/"},
		{name: "encoded backslash authority", queryNext: "%2F%5C%5Cevil.example%2Fpath", want: "/"},
		{name: "absolute URL", queryNext: "https%3A%2F%2Fevil.example%2Fpath", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newDashboardTestMux(t, nil, "correct-horse-battery-staple")
			r := httptest.NewRequest(http.MethodPost, "/__login?next="+tt.queryNext, strings.NewReader("password=correct-horse-battery-staple"))
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

// TestDashboardLoginFirstRunCreatesRootAndSetsCookie verifies the
// first-run flow: with no root row, POSTing matching password+
// confirm fields creates the row, sets the cookie, and redirects.
func TestDashboardLoginFirstRunCreatesRootAndSetsCookie(t *testing.T) {
	w := newDashboardTestMux(t, nil, "")

	const pw = "first-run-passphrase-1234"
	body := strings.NewReader("password=" + pw + "&confirm=" + pw)
	r := httptest.NewRequest(http.MethodPost, "/__login?next=/", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %s)", rw.Code, http.StatusFound, rw.Body.String())
	}
	var got *http.Cookie
	for _, c := range rw.Result().Cookies() {
		if c.Name == cpDashCookieName {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatal("no cp_dash cookie set after first-run setup")
	}
	if got.Value != pw {
		t.Fatalf("cp_dash cookie value = %q, want %q", got.Value, pw)
	}
	// The row should now exist.
	if _, exists, err := lookupDashboardUser(w.g.db, dashboardRootUsername); err != nil {
		t.Fatalf("lookup root: %v", err)
	} else if !exists {
		t.Fatal("root row was not persisted")
	}
}

func TestDashboardLoginFirstRunMismatchRejected(t *testing.T) {
	w := newDashboardTestMux(t, nil, "")

	body := strings.NewReader("password=first-run-passphrase-1234&confirm=different-passphrase-1234")
	r := httptest.NewRequest(http.MethodPost, "/__login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusBadRequest)
	}
	if _, exists, _ := lookupDashboardUser(w.g.db, dashboardRootUsername); exists {
		t.Fatal("root row should not exist after mismatched first-run")
	}
}

func TestDashboardLoginFirstRunRejectsShortPassword(t *testing.T) {
	w := newDashboardTestMux(t, nil, "")

	body := strings.NewReader("password=short&confirm=short")
	r := httptest.NewRequest(http.MethodPost, "/__login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.apiDashboardLogin(rw, r)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusBadRequest)
	}
}
