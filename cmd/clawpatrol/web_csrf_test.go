package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// csrfTestHost is the hostname the test gateway answers for — it
// matches the publicURL the shared test mux is built with, so it
// passes the Host allowlist and leaves the origin headers as the only
// thing under test.
const csrfTestHost = "gateway.example.test"

// newCSRFTestWebMux builds a mux in the configuration that makes the
// CSRF surface reachable: Tailscale control mode with a populated
// dashboard_operators allowlist, and a whois that resolves the
// calling peer to a matching login. In that configuration
// dashboardAuthGate hands every cookieless request to tailnetGate,
// which authenticates it from the peer address — so a cross-site
// request, which SameSite=Lax strips the cp_session cookie from,
// arrives fully authorized unless csrfProtect stops it.
func newCSRFTestWebMux(t *testing.T) *webMux {
	t.Helper()
	w := newOnboardAuthTestWebMuxForControl(t, "tailscale")
	w.g.cfg.Load().Settings.Tailscale.Operators = []string{"*@example.com"}
	withTailnetPeer(w, "operator@example.com")
	w.g.hitl = newHITLRegistry(nil)
	return w
}

// csrfTestRequest builds a POST from the allowlisted tailnet peer to
// path with body, carrying no session cookie — the shape a cross-site
// request has once SameSite=Lax withholds the cookie.
func csrfTestRequest(method, path, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Host = csrfTestHost
	fromTailnetPeer(req)
	return req
}

func serveCSRF(w *webMux, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	w.handler().ServeHTTP(rr, req)
	return rr
}

// csrfDenied asserts the response is the middleware's refusal rather
// than any answer the handler behind it produced.
func csrfDenied(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "CSRF request denied") {
		t.Fatalf("body = %q, want a CSRF denial", rr.Body.String())
	}
}

// csrfNotDenied asserts the middleware let the request through to the
// stack behind it, whatever that stack then decided.
func csrfNotDenied(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(rr.Body.String(), "CSRF request denied") {
		t.Fatalf("status = %d body = %q: request was denied by csrfProtect, want pass-through", rr.Code, rr.Body.String())
	}
}

// csrfProtectedPaths are the state-changing endpoints that the
// dashboardAuthGate → tailnetGate fallthrough leaves reachable
// without a session cookie. Each carries a body its handler accepts
// so that a request which gets through shows up as the handler's own
// answer, not a decode error.
var csrfProtectedPaths = []struct {
	name string
	path string
	body string
}{
	{name: "onboard approve", path: "/api/onboard/approve", body: `{"code":"NOPE","profile":"default"}`},
	{name: "credentials set", path: "/api/credentials/set", body: `{}`},
	{name: "config apply", path: "/api/config/apply", body: `{}`},
	{name: "hitl decide", path: "/api/hitl/decide", body: `{"id":"nope","allow":true}`},
}

// A browser that reports the request as cross-site must be refused on
// every one of these paths. Without csrfProtect each one reaches its
// handler: the operator allowlist is satisfied by the peer address
// alone, which is precisely what a cookieless request falls back to.
func TestCSRFRejectsCrossSiteStateChangingRequests(t *testing.T) {
	for _, tc := range csrfProtectedPaths {
		t.Run(tc.name, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, tc.path, tc.body)
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			csrfDenied(t, serveCSRF(w, req))
		})
	}
}

// The same paths, attacked the way a plain cross-origin HTML form
// reaches them: no Sec-Fetch-Site (older browser or plain-HTTP
// origin), a foreign Origin, and a form content type.
func TestCSRFRejectsForeignOriginStateChangingRequests(t *testing.T) {
	for _, tc := range csrfProtectedPaths {
		t.Run(tc.name, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, tc.path, tc.body)
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			csrfDenied(t, serveCSRF(w, req))
		})
	}
}

// Origin == Host is satisfied by a DNS rebinding attack: the
// attacker's name resolves to the gateway, so the browser considers
// its own page same-origin with the dashboard and says so. Comparing
// the two headers against each other cannot catch that; only
// requiring Host to be a name the gateway answers for can.
func TestCSRFRejectsRebindingWithForeignHost(t *testing.T) {
	for _, tc := range csrfProtectedPaths {
		t.Run(tc.name, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, tc.path, tc.body)
			req.Host = "rebound.evil.example"
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Origin", "https://rebound.evil.example")
			csrfDenied(t, serveCSRF(w, req))
		})
	}
}

// "Origin: null" — a form POST from a sandboxed iframe or a data:
// URL — must not satisfy the comparison.
func TestCSRFRejectsNullOrigin(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Header.Set("Origin", "null")
	csrfDenied(t, serveCSRF(w, req))
}

// The no-lockout half. The dashboard's own fetches report
// same-origin against a Host the gateway answers for, and must reach
// their handlers — each one's own answer proves it did.
func TestCSRFAllowsSameSiteStateChangingRequests(t *testing.T) {
	wants := map[string]string{
		"onboard approve": "unknown or expired code",
		"credentials set": "missing id",
		"config apply":    "append_hcl is required",
		"hitl decide":     "unknown or expired HITL request",
	}
	for _, tc := range csrfProtectedPaths {
		t.Run(tc.name, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, tc.path, tc.body)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Origin", "https://"+csrfTestHost)
			rr := serveCSRF(w, req)
			csrfNotDenied(t, rr)
			if want := wants[tc.name]; !strings.Contains(rr.Body.String(), want) {
				t.Fatalf("body = %q, want the handler's own answer %q", rr.Body.String(), want)
			}
		})
	}
}

// Same-origin over plain HTTP, where Sec-Fetch-Site is absent and the
// Origin/Host comparison is the only signal. Reached by IP, which the
// Host allowlist accepts because an IP literal cannot be rebound.
func TestCSRFAllowsSameOriginByIPWithoutSecFetchSite(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "100.64.0.1:8080"
	req.Header.Set("Origin", "http://100.64.0.1:8080")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// The `clawpatrol` CLI posts to operator-gated endpoints with no
// browser headers at all — `join --login` self-approval is the live
// case. Every browser sets Origin on a non-GET request, so nothing a
// page can drive lands in this bucket, and rejecting it would turn
// each such call into a 403.
func TestCSRFAllowsCLIWithoutBrowserHeaders(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/onboard/approve?code=NOPE&profile=default", "")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

// The one thing a cross-site page could still express if a client
// omitted both headers is a form submission, so the header-less
// allowance stops at the three content types a form can produce.
func TestCSRFRejectsFormContentTypeWithoutBrowserHeaders(t *testing.T) {
	for _, ct := range []string{
		"application/x-www-form-urlencoded",
		"multipart/form-data; boundary=x",
		"text/plain;charset=UTF-8",
	} {
		t.Run(ct, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, "/api/config/apply", "")
			req.Header.Set("Content-Type", ct)
			csrfDenied(t, serveCSRF(w, req))
		})
	}
}

// Credential webhooks are authSelfAuthenticating and must stay exempt.
// Slack's interactive callback is the live caller: it posts
// form-urlencoded with no Origin and no Sec-Fetch-Site, proving itself
// with a v0 HMAC signature instead — exactly the shape the header-less
// form-content-type rule refuses everywhere else. Reaching the mux and
// 404ing (no credential mounts this route in the test gateway) shows
// csrfProtect passed it.
func TestCSRFExemptsCredentialWebhooksWithoutOrigin(t *testing.T) {
	w := newCSRFTestWebMux(t)
	const path = "/api/cred/slack/interactive"
	if got := w.authRequirementForPath(path); got != authSelfAuthenticating {
		t.Fatalf("authRequirementForPath(%q) = %v, want authSelfAuthenticating", path, got)
	}
	req := csrfTestRequest(http.MethodPost, path, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

// The HITL operation-status paths are self-authenticating too (a
// per-operation status token). A non-GET must reach the handler and
// get its 405, not a CSRF refusal.
func TestCSRFExemptsHITLOperationStatusWithoutOrigin(t *testing.T) {
	w := newCSRFTestWebMux(t)
	path := hitlOperationStatusPrefix + "op-1" + hitlOperationStatusSuffix
	if got := w.authRequirementForPath(path); got != authSelfAuthenticating {
		t.Fatalf("authRequirementForPath(%q) = %v, want authSelfAuthenticating", path, got)
	}
	req := csrfTestRequest(http.MethodPost, path, "")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
	}
}

// GET is not state-changing, so the dashboard keeps rendering for a
// cross-site navigation rather than breaking on the origin check.
func TestCSRFIgnoresGETRequests(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodGet, "/api/hitl/pending", "")
	req.Host = "rebound.evil.example"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	csrfNotDenied(t, serveCSRF(w, req))
}

func TestCSRFHostAllowlist(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.g.tailscaleHostname = "claw-gw"
	w.g.cfg.Load().Settings.DashboardListen = "0.0.0.0:8080"

	allowed := []string{
		"gateway.example.test",            // publicURL
		"GATEWAY.EXAMPLE.TEST",            // case-insensitive
		"gateway.example.test:8080",       // with a port
		"127.0.0.1:8080",                  // IP literal
		"100.64.0.1",                      // tailnet IP literal
		"[::1]:8080",                      // IPv6 literal
		"localhost:8080",                  // loopback name
		"dash.localhost",                  // loopback subdomain
		"claw-gw:8080",                    // bare MagicDNS label
		"claw-gw.tailnet-abc.ts.net:8080", // full MagicDNS name
	}
	for _, host := range allowed {
		if !w.csrfHostAllowed(host) {
			t.Errorf("csrfHostAllowed(%q) = false, want true", host)
		}
	}

	denied := []string{
		"",
		"evil.example",
		"gateway.example.test.evil.example",
		"claw-gw.evil.example", // MagicDNS label outside the ts.net suffix
		"notgateway.example.test",
	}
	for _, host := range denied {
		if w.csrfHostAllowed(host) {
			t.Errorf("csrfHostAllowed(%q) = true, want false", host)
		}
	}
}

// A wildcard bind names no host, so it must not widen the allowlist.
func TestCSRFHostAllowlistIgnoresWildcardBind(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, listen := range []string{"0.0.0.0:8080", ":8080", "[::]:8080"} {
		w.g.cfg.Load().Settings.DashboardListen = listen
		if w.csrfHostAllowed("evil.example") {
			t.Errorf("dashboard_listen %q widened the allowlist", listen)
		}
	}
}

// A named bind address is a host the dashboard answers for.
func TestCSRFHostAllowlistAcceptsNamedBind(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.g.cfg.Load().Settings.DashboardListen = "dash.internal:8080"
	if !w.csrfHostAllowed("dash.internal:8080") {
		t.Error("named dashboard_listen host was not allowed")
	}
}

// /api/onboard/approve takes its parameters from a JSON body. A
// state-changing call whose inputs ride in the URL is reachable by
// navigation and lands in logs and history.
func TestOnboardApproveReadsCodeAndProfileFromJSONBody(t *testing.T) {
	w := newCSRFTestWebMux(t)
	h := w.handler()

	startReq := httptest.NewRequest(http.MethodPost, "/api/onboard/start?hostname=body-device", nil)
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("start status = %d; body = %q", startRR.Code, startRR.Body.String())
	}
	var start struct {
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(startRR.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	if start.UserCode == "" {
		t.Fatal("start returned no user_code")
	}

	req := csrfTestRequest(http.MethodPost, "/api/onboard/approve", `{"code":"`+start.UserCode+`","profile":"default"}`)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rr := serveCSRF(w, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want %d; body = %q", rr.Code, http.StatusOK, rr.Body.String())
	}
	s := w.onboard.byUserCode(start.UserCode)
	if s == nil {
		t.Fatal("pending session vanished")
	}
	if !s.approved {
		t.Fatal("session not marked approved from a JSON-body approve")
	}
	if s.profile != "default" {
		t.Fatalf("profile = %q, want %q", s.profile, "default")
	}
}

// A body that is not JSON is a caller error, not a silent fallback to
// the query string.
func TestOnboardApproveRejectsNonJSONBody(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/onboard/approve", "code=NOPE")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rr := serveCSRF(w, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "body must be JSON") {
		t.Fatalf("body = %q, want a JSON decode error", rr.Body.String())
	}
}

// apiPluginApprove writes clawpatrol.lock.hcl and reloads the
// gateway, so it must not answer anything but POST.
func TestPluginApproveRejectsNonPOST(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := csrfTestRequest(method, "/api/plugins/approve", "")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rr := serveCSRF(w, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want %d; body = %q", method, rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
		}
	}
}

// apiActionByID only reads. The dashboard fetches it with a plain GET
// and an operator can navigate to the URL, so anything else is a
// caller error.
func TestActionByIDRejectsNonGET(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := csrfTestRequest(method, "/api/actions/some-id", "")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rr := serveCSRF(w, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want %d; body = %q", method, rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
		}
	}
}

// A proxy in front of the dashboard may forward a backend Host —
// nginx's `proxy_pass` default rewrites it — while the browser's
// origin stays the external hostname. Checking Origin against the
// names the gateway answers for, rather than against the request's
// own Host, is what keeps those deployments working: `public_url` is
// the operator's declaration of that external hostname.
func TestCSRFAllowsProxiedRequestWithRewrittenHost(t *testing.T) {
	for _, backendHost := range []string{"clawpatrol:8080", "127.0.0.1:8080", "10.0.0.7:8080"} {
		t.Run(backendHost, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
			req.Host = backendHost
			req.Header.Set("Origin", "https://"+csrfTestHost)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			rr := serveCSRF(w, req)
			csrfNotDenied(t, rr)
			if !strings.Contains(rr.Body.String(), "append_hcl is required") {
				t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
			}
		})
	}
}

// The same proxy shape without Sec-Fetch-Site — a plain-HTTP external
// origin — must also survive, since Host cannot be compared against
// Origin behind a proxy that rewrote it.
func TestCSRFAllowsProxiedRequestWithoutSecFetchSite(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "clawpatrol:8080"
	req.Header.Set("Origin", "http://"+csrfTestHost)
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// Sec-Fetch-Site: same-origin is not sufficient on its own. A rebound
// page is genuinely same-origin with the dashboard and reports itself
// that way, so the Origin it carries still has to name the gateway.
func TestCSRFRejectsRebindingReportingSameOrigin(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/credentials/set", `{"id":"x"}`)
	req.Host = "rebound.evil.example"
	req.Header.Set("Origin", "https://rebound.evil.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	csrfDenied(t, serveCSRF(w, req))
}

// The Origin is matched as a full authority, so a page the agent
// serves from an address or a port of its own is a different origin
// and is refused — even though csrfHostAllowed, which judges the
// destination, is deliberately loose about ports and accepts any IP
// literal. The agent runs on the operator's machine, so a local
// listener on another port is the cheapest forgery available to it.
func TestCSRFRejectsForeignOriginAuthorities(t *testing.T) {
	cases := []struct {
		name        string
		requestHost string
		origin      string
	}{
		{name: "attacker IP literal", requestHost: "100.64.0.1:8080", origin: "http://203.0.113.5"},
		{name: "attacker IP with port", requestHost: "100.64.0.1:8080", origin: "http://203.0.113.5:8080"},
		{name: "other port on loopback", requestHost: "127.0.0.1:8080", origin: "http://127.0.0.1:9999"},
		{name: "other port on localhost", requestHost: "localhost:8080", origin: "http://localhost:9999"},
		{name: "other port on public_url host", requestHost: csrfTestHost, origin: "https://" + csrfTestHost + ":9999"},
		{name: "other port on MagicDNS name", requestHost: "claw-gw:8080", origin: "http://claw-gw:9999"},
		{name: "loopback page against tailnet host", requestHost: "100.64.0.1:8080", origin: "http://127.0.0.1:8080"},
		{name: "foreign tailnet MagicDNS name", requestHost: "claw-gw:8080", origin: "http://claw-gw.other-tailnet.ts.net:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			w.g.tailscaleHostname = "claw-gw"
			req := csrfTestRequest(http.MethodPost, "/api/credentials/set", `{"id":"x"}`)
			req.Host = tc.requestHost
			req.Header.Set("Origin", tc.origin)
			// Sec-Fetch-Site is absent, the plain-HTTP shape, so the
			// Origin comparison is the only thing deciding.
			csrfDenied(t, serveCSRF(w, req))
		})
	}
}

// The matching authorities those cases are varied from, so the
// rejections above are attributable to the authority and not to the
// harness.
func TestCSRFAllowsMatchingOriginAuthorities(t *testing.T) {
	cases := []struct {
		name        string
		requestHost string
		origin      string
	}{
		{name: "loopback with port", requestHost: "127.0.0.1:8080", origin: "http://127.0.0.1:8080"},
		{name: "localhost with port", requestHost: "localhost:8080", origin: "http://localhost:8080"},
		{name: "tailnet IP with port", requestHost: "100.64.0.1:8080", origin: "http://100.64.0.1:8080"},
		{name: "MagicDNS name with port", requestHost: "claw-gw:8080", origin: "http://claw-gw:8080"},
		{name: "public_url host", requestHost: csrfTestHost, origin: "https://" + csrfTestHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			w.g.tailscaleHostname = "claw-gw"
			req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
			req.Host = tc.requestHost
			req.Header.Set("Origin", tc.origin)
			rr := serveCSRF(w, req)
			csrfNotDenied(t, rr)
			if !strings.Contains(rr.Body.String(), "append_hcl is required") {
				t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
			}
		})
	}
}

// public_url is an additional accepted origin, not a replacement for
// the request's own: it is the join-link and OAuth-redirect URL, and
// an operator who sets it still reaches the dashboard on loopback.
func TestCSRFPublicURLDoesNotDisplaceLoopbackOrigin(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "localhost:8080"
	req.Header.Set("Origin", "http://localhost:8080")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// A public_url carrying a port must match on that port too.
func TestCSRFPublicURLPortIsPartOfTheMatch(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.publicURL = "http://gw.example.test:8080"
	w.g.cfg.Load().Settings.PublicURL = "http://gw.example.test:8080"

	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "backend:9090"
	req.Header.Set("Origin", "http://gw.example.test:8080")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)

	bad := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	bad.Host = "backend:9090"
	bad.Header.Set("Origin", "http://gw.example.test:9999")
	csrfDenied(t, serveCSRF(w, bad))
}
