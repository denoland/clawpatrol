package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// csrfReadDenied asserts the response is csrfProtectRead's refusal
// rather than any answer the handler behind it produced.
func csrfReadDenied(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "denied") {
		t.Fatalf("body = %q, want a refusal", rr.Body.String())
	}
}

// csrfReadPassed asserts the read reached its handler and was answered.
func csrfReadPassed(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusOK, rr.Body.String())
	}
}

// The read surface the dashboard exposes is what a DNS-rebinding page
// is after, and it is reachable without any header to compare: a
// browser sends no Origin on a GET. The page holds no cp_session —
// that cookie belongs to the dashboard's real origin — and a cookieless
// request is the one dashboardAuthGate hands to tailnetGate, which
// takes its principal from the peer address. So the Host is the only
// thing that distinguishes the operator's own dashboard from a name the
// attacker rebound onto the gateway.
func TestCSRFRejectsRebindingReads(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, path := range []string{
		"/api/state",
		"/api/config",
		"/api/events",
		"/api/hitl/pending",
		"/api/onboard/lookup?code=NOPE",
		"/api/status",
		"/api/rules",
		"/api/analytics",
		"/",
	} {
		t.Run(path, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, path, "")
			// The rebound name: the page was served from it, so the
			// browser addresses the request to it and reports the
			// request as same-origin, which it is.
			req.Host = "rebound.evil.example"
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			csrfReadDenied(t, serveCSRF(w, req))
		})
	}
}

// The same reads must still answer when the dashboard is addressed by a
// name the gateway answers for.
func TestCSRFAllowsOwnHostReads(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, path := range []string{"/api/state", "/api/status", "/api/rules"} {
		t.Run(path, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, path, "")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			csrfReadPassed(t, serveCSRF(w, req))
		})
	}
}

// An IP literal cannot be rebound — for the page to be same-origin with
// the request it was served from this same address, which is the
// gateway — so the tsnet and loopback addresses the dashboard is
// actually reached on stay readable.
func TestCSRFAllowsLiteralAndLoopbackHostReads(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, host := range []string{
		"100.64.0.1:8080",
		"127.0.0.1:8080",
		"[fd7a:115c:a1e0::1]:8080",
		"localhost:8080",
	} {
		t.Run(host, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, "/api/state", "")
			req.Host = host
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			csrfReadPassed(t, serveCSRF(w, req))
		})
	}
}

// A proxy or CNAME in front of the dashboard rewrites Host to a name
// the gateway cannot derive from itself. `dashboard_hosts` is where the
// operator declares it; without the declaration the read is refused,
// which is the whole point of holding reads to a set.
func TestCSRFDashboardHostsAdmitsDeclaredName(t *testing.T) {
	w := newCSRFTestWebMux(t)

	req := csrfTestRequest(http.MethodGet, "/api/state", "")
	req.Host = "clawpatrol-backend:8080"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	csrfReadDenied(t, serveCSRF(w, req))

	w.g.cfg.Load().Settings.DashboardHosts = []string{"clawpatrol-backend"}
	req = csrfTestRequest(http.MethodGet, "/api/state", "")
	req.Host = "clawpatrol-backend:8080"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	csrfReadPassed(t, serveCSRF(w, req))
}

// Entries may be written as a bare name, with a port, or as a URL; the
// set judges the name alone.
func TestCSRFDashboardHostsEntryForms(t *testing.T) {
	for _, entry := range []string{
		"clawpatrol-backend",
		"clawpatrol-backend:8080",
		"https://clawpatrol-backend",
		"https://clawpatrol-backend:8080",
		"CLAWPATROL-BACKEND",
	} {
		t.Run(entry, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			w.g.cfg.Load().Settings.DashboardHosts = []string{entry}
			req := csrfTestRequest(http.MethodGet, "/api/state", "")
			req.Host = "clawpatrol-backend:8080"
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			csrfReadPassed(t, serveCSRF(w, req))
		})
	}
}

// A declared name admits that name and nothing adjacent to it.
func TestCSRFDashboardHostsIsNotASuffixMatch(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.g.cfg.Load().Settings.DashboardHosts = []string{"clawpatrol-backend"}
	for _, host := range []string{
		"clawpatrol-backend.evil.example",
		"evil-clawpatrol-backend",
		"notclawpatrol-backend",
	} {
		t.Run(host, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, "/api/state", "")
			req.Host = host
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			csrfReadDenied(t, serveCSRF(w, req))
		})
	}
}

// A browser that names another site as the initiator of an API read has
// said so outright. CORS already withholds the response from such a
// page; this is the second lock on the same door.
func TestCSRFRejectsCrossSiteAPIRead(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, site := range []string{"cross-site", "same-site"} {
		t.Run(site, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, "/api/state", "")
			req.Header.Set("Sec-Fetch-Site", site)
			csrfReadDenied(t, serveCSRF(w, req))
		})
	}
}

// A client with no Sec-Fetch headers at all is the `clawpatrol` daemon
// and an operator's curl. A browser always sets the header, so a page
// cannot land in this bucket; rejecting it would only break the
// non-browser callers. "none" is the user themself — a typed URL or a
// bookmark.
func TestCSRFAllowsAPIReadWithoutSecFetchSite(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, site := range []string{"", "none", "same-origin"} {
		t.Run("site="+site, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, "/api/state", "")
			if site != "" {
				req.Header.Set("Sec-Fetch-Site", site)
			}
			csrfReadPassed(t, serveCSRF(w, req))
		})
	}
}

// Document paths are held to the Host but not to Sec-Fetch-Site: a
// top-level navigation into the dashboard from a link elsewhere reports
// "cross-site", and from a page on a sibling name "same-site". Both are
// legitimate ways to arrive, and neither can read the response.
func TestCSRFAllowsCrossSiteNavigationToDashboard(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, site := range []string{"cross-site", "same-site", "none"} {
		t.Run(site, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, "/", "")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", site)
			csrfNotDenied(t, serveCSRF(w, req))
		})
	}
}

// The unauthenticated surface stays open to any Host. None of it is
// gated, so none of it is anything a rebound name unlocks — and
// `clawpatrol join` reaches it by whatever URL the operator typed,
// which the gateway cannot derive from itself.
func TestCSRFLeavesPublicReadsOpenToAnyHost(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, path := range []string{"/info", "/__login", "/claw-patrol-logo.svg"} {
		t.Run(path, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, path, "")
			req.Host = "whatever.example"
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			csrfNotDenied(t, serveCSRF(w, req))
		})
	}
}

// A self-authenticating read carries its own proof per request — a peer
// bearer token here — which a page cannot produce, so the response is
// not one a rebound name unlocks either.
func TestCSRFLeavesSelfAuthenticatingReadsOpenToAnyHost(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, path := range []string{"/api/env-pushdown", "/api/hitl/operations/nope/status"} {
		t.Run(path, func(t *testing.T) {
			req := csrfTestRequest(http.MethodGet, path, "")
			req.Host = "whatever.example"
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			csrfNotDenied(t, serveCSRF(w, req))
		})
	}
}

// A read with no Host at all names nothing the gateway answers for.
func TestCSRFRejectsReadWithNoHost(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodGet, "/api/state", "")
	req.Host = ""
	csrfReadDenied(t, serveCSRF(w, req))
}
