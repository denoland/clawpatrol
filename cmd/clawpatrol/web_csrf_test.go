package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/tailscaleproto"
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
	w.g.cfg.Load().Settings.PublicURL = "https://" + csrfTestHost
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
	hostNotRefused(t, rr)
}

// serveCSRFOnly runs req through csrfProtect alone, with a marker
// handler behind it, so the origin check can be exercised on a Host
// that hostGate — which sits outside it in the real chain — would
// refuse first. The two layers overlap on a rebound name by design;
// this keeps the inner one's own verdict observable.
func serveCSRFOnly(w *webMux, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	w.csrfProtect(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte(csrfMarkerBody))
	})).ServeHTTP(rr, req)
	return rr
}

const csrfMarkerBody = "reached the handler"

// hostRefused asserts the response is hostGate's refusal and nothing
// else: a 421 whose body is the one-line notice, with no output from
// anything behind the gate.
func hostRefused(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusMisdirectedRequest, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.HasPrefix(body, "Request refused: Host ") {
		t.Fatalf("body = %q, want the host gate's refusal", body)
	}
	if strings.Count(body, "\n") != 1 || !strings.HasSuffix(body, "\n") {
		t.Fatalf("body = %q, want a single line and nothing from behind the gate", body)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

// hostNotRefused asserts hostGate let the request through, whatever
// the stack behind it then decided.
func hostNotRefused(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code == http.StatusMisdirectedRequest || strings.HasPrefix(rr.Body.String(), "Request refused: Host ") {
		t.Fatalf("status = %d body = %q: request was refused by hostGate, want pass-through", rr.Code, rr.Body.String())
	}
}

// setTsnetSelf publishes the node identity control would have
// reported: the registered name and its full MagicDNS form.
func setTsnetSelf(w *webMux, hostname, dnsName string) {
	w.g.tsnetSelf.Store(&tsnetIdentity{Hostname: hostname, DNSName: dnsName})
}

// onboardSessionCount reports how many device-flow sessions the
// registry holds, by either code.
func onboardSessionCount(r *onboardRegistry) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byDevice) + len(r.byUser)
}

// csrfBindAs declares host as the dashboard's bind address, the way a
// deployment whose proxy rewrites Host to a backend name has to: the
// gateway only answers for names it knows are its own, and a bind
// hostname is one of them.
func csrfBindAs(w *webMux, host string) {
	w.g.cfg.Load().Settings.DashboardListen = host
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
// requiring Host to be a name the gateway answers for can. hostGate
// does that for every request before the chain runs; csrfProtect
// keeps its own copy of the check for writes.
func TestCSRFRejectsRebindingWithForeignHost(t *testing.T) {
	for _, tc := range csrfProtectedPaths {
		t.Run(tc.name, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, tc.path, tc.body)
			req.Host = "rebound.evil.example"
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Origin", "https://rebound.evil.example")
			hostRefused(t, serveCSRF(w, req))
			csrfDenied(t, serveCSRFOnly(w, req))
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

// GET is not state-changing, so the origin check lets a cross-site
// navigation through rather than breaking the dashboard on it. What
// it must still address is the gateway's own name: a rebound GET is
// how a page reads the dashboard's JSON, and hostGate is what refuses
// it — see TestHostGate*.
func TestCSRFIgnoresGETRequests(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodGet, "/api/hitl/pending", "")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusOK, rr.Body.String())
	}

	// The same GET on a rebound name is refused — not by csrfProtect,
	// which is deliberately blind to GET, but by the gate outside it.
	rebound := csrfTestRequest(http.MethodGet, "/api/hitl/pending", "")
	rebound.Host = "rebound.evil.example"
	rebound.Header.Set("Sec-Fetch-Site", "cross-site")
	hostRefused(t, serveCSRF(w, rebound))
	if rr := serveCSRFOnly(w, rebound); rr.Body.String() != csrfMarkerBody {
		t.Fatalf("csrfProtect alone: body = %q, want pass-through of a GET", rr.Body.String())
	}
}

// hostGateTestHosts are the names the test gateway serves the
// dashboard on, one per clause of csrfHostAllowed, each as a browser
// would send it: public_url host, IP literals, loopback, and the tsnet
// node's MagicDNS label both bare and fully qualified.
var hostGateTestHosts = []string{
	csrfTestHost,                    // public_url host
	"100.64.0.1:8080",               // tailnet IP literal
	"[::1]:8080",                    // IPv6 literal
	"localhost:8080",                // loopback name
	"claw-gw:8080",                  // bare MagicDNS label
	"claw-gw.tailnet-abc.ts.net",    // full MagicDNS name (Funnel)
	"claw-gw.headscale.example.org", // full name on a custom control plane
}

// A rebound read: the page on attacker.example resolves that name to
// the gateway and GETs the dashboard's JSON through it. Nothing about
// the request is wrong except its Host, so the Host is what refuses
// it, and before anything behind the gate produces output.
func TestHostGateRefusesForeignHostOnReads(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodGet, "/api/state", "")
	req.Host = "rebound.evil.example:8080"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rr := serveCSRF(w, req)
	hostRefused(t, rr)
	if !strings.Contains(rr.Body.String(), `"rebound.evil.example:8080"`) {
		t.Fatalf("body = %q, want the refused Host named", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "public_url") {
		t.Fatalf("body = %q, want the public_url remedy", rr.Body.String())
	}
}

// Each of the gateway's own names passes the gate, whatever the stack
// behind it then answers for /api/state.
func TestHostGateAcceptsOwnNames(t *testing.T) {
	for _, host := range hostGateTestHosts {
		t.Run(host, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			setTsnetSelf(w, "claw-gw", "claw-gw.headscale.example.org")
			req := csrfTestRequest(http.MethodGet, "/api/state", "")
			req.Host = host
			hostNotRefused(t, serveCSRF(w, req))
		})
	}
}

// The gate is method-blind: HEAD and OPTIONS, which csrfProtect also
// skips, are refused on a foreign Host like everything else.
func TestHostGateRefusesHeadAndOptions(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(method, "/api/state", "")
			req.Host = "rebound.evil.example"
			hostRefused(t, serveCSRF(w, req))
		})
	}
}

// The Funnel listener carries the node's .ts.net name on every
// request it forwards: the credential webhooks and the device-flow
// handshake `clawpatrol join` drives both reach their handlers on it.
func TestHostGateAdmitsFunnelHost(t *testing.T) {
	const funnelHost = "claw-gw.tailnet-abc.ts.net"
	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/api/cred/slack/interactive", want: http.StatusNotFound},
		{path: "/api/onboard/start?hostname=funnel-device", want: http.StatusOK},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			setTsnetSelf(w, "claw-gw", "")
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Host = funnelHost
			rr := serveCSRF(w, req)
			csrfNotDenied(t, rr)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body = %q", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// Public and self-authenticating routes are not exempt from the gate
// the way they are from the origin check: a rebound name is refused
// whatever the route asks for.
func TestHostGateRefusesForeignHostOnPublicRoutes(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, dashboardLoginPath},
		{http.MethodGet, "/info"},
		{http.MethodPost, "/api/onboard/start?hostname=x"},
		{http.MethodPost, "/api/cred/slack/interactive"},
		{http.MethodGet, hitlOperationStatusPrefix + "op-1" + hitlOperationStatusSuffix},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Host = "rebound.evil.example"
			hostRefused(t, serveCSRF(w, req))
			// The refusal happened before the handler: a refused
			// /api/onboard/start must not have opened a session.
			if n := onboardSessionCount(w.onboard); n != 0 {
				t.Fatalf("onboard registry holds %d session(s) after a refused request, want 0", n)
			}
		})
	}
}

// hostGate on its own, with nothing but a tripwire behind it: a
// foreign Host never reaches the next handler.
func TestHostGateNeverCallsNextOnForeignHost(t *testing.T) {
	w := newCSRFTestWebMux(t)
	gate := w.hostGate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler behind hostGate reached on a foreign Host")
	}))
	req := csrfTestRequest(http.MethodGet, "/api/state", "")
	req.Host = "rebound.evil.example"
	rr := httptest.NewRecorder()
	gate.ServeHTTP(rr, req)
	hostRefused(t, rr)
}

// Until control reports the registered node name, the configured one
// stands in for it, so a dashboard reached by name is not refused for
// as long as control is slow to answer. Once the registered name is
// known it is the only one that counts.
func TestHostGateFallsBackToConfiguredTsnetName(t *testing.T) {
	w := newCSRFTestWebMux(t)
	ts := w.g.cfg.Load().Settings.Tailscale
	ts.Hostname = "claw-gw"
	for _, host := range []string{"claw-gw:8080", "claw-gw.tailnet-abc.ts.net"} {
		req := csrfTestRequest(http.MethodGet, "/api/state", "")
		req.Host = host
		hostNotRefused(t, serveCSRF(w, req))
	}
	if w.csrfHostAllowed("claw-gw.evil.example") {
		t.Error("configured label was accepted outside the .ts.net suffix")
	}

	// An unset tailscale.hostname means the node asked for the default.
	ts.Hostname = ""
	req := csrfTestRequest(http.MethodGet, "/api/state", "")
	req.Host = defaultTsnetHostname + ":8080"
	hostNotRefused(t, serveCSRF(w, req))
	if w.csrfHostAllowed("claw-gw:8080") {
		t.Error("a configured name that was unset is still allowed")
	}

	// Once control has reported the registered name the configured one
	// no longer stands in: tsnet may have renamed the node on conflict.
	ts.Hostname = "claw-gw"
	setTsnetSelf(w, "claw-gw-1", "claw-gw-1.tailnet-abc.ts.net")
	if w.csrfHostAllowed("claw-gw:8080") {
		t.Error("configured name still allowed once the registered name is known")
	}
	for _, host := range []string{"claw-gw-1:8080", "claw-gw-1.tailnet-abc.ts.net"} {
		if !w.csrfHostAllowed(host) {
			t.Errorf("registered name %q not allowed", host)
		}
	}
}

// The fallback is a tsnet thing: a WireGuard-only gateway has no node
// and so no node name to answer for.
func TestHostGateNoConfiguredTsnetNameInWireGuardMode(t *testing.T) {
	w := newOnboardAuthTestWebMuxForControl(t, "wireguard")
	for _, host := range []string{defaultTsnetHostname + ":8080", defaultTsnetHostname + ".tailnet-abc.ts.net"} {
		if w.csrfHostAllowed(host) {
			t.Errorf("csrfHostAllowed(%q) = true in WireGuard mode, want false", host)
		}
	}
}

// A request with no Host at all (HTTP/1.0 without the header) names
// nothing the gateway serves, so it is refused too.
func TestHostGateRefusesMissingHost(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodGet, "/info", "")
	req.Host = ""
	hostRefused(t, serveCSRF(w, req))
}

func TestCSRFHostAllowlist(t *testing.T) {
	w := newCSRFTestWebMux(t)
	setTsnetSelf(w, "claw-gw", "claw-gw.headscale.example.org")
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
		"claw-gw.headscale.example.org",   // full name on a custom control plane
		"CLAW-GW.Headscale.Example.org.",  // same, as a browser may spell it
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
		"other.headscale.example.org", // custom base domain, other node
		"claw-gw.headscale.example.org.evil.example",
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

// A configured name spelled as an absolute FQDN, with the trailing
// dot, names the same host as the request's spelling without it.
func TestCSRFHostAllowlistCanonicalizesConfiguredTrailingDot(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.g.cfg.Load().Settings.PublicURL = "https://gw.example.test."
	w.g.cfg.Load().Settings.DashboardListen = "dash.internal.:8080"
	for _, host := range []string{"gw.example.test", "gw.example.test.", "dash.internal:8080", "dash.internal."} {
		if !w.csrfHostAllowed(host) {
			t.Errorf("csrfHostAllowed(%q) = false, want true", host)
		}
	}
	if w.csrfHostAllowed("gw.example.test.evil.example") {
		t.Error("trailing-dot public_url matched as a prefix")
	}
}

// The refusal log quotes and caps request-derived fields: a control
// character cannot forge a line and a header-sized Host cannot grow
// the log by itself.
func TestHostGateLogFieldQuotesAndCaps(t *testing.T) {
	if got := hostGateLogField("evil\nweb: forged"); strings.Contains(got, "\n") || got != `"evil\nweb: forged"` {
		t.Fatalf("hostGateLogField = %s, want control characters escaped", got)
	}
	long := strings.Repeat("a", 4*hostGateLogFieldMax)
	got := hostGateLogField(long)
	if len(got) > hostGateLogFieldMax+64 || !strings.HasSuffix(got, fmt.Sprintf("(%d bytes)", len(long))) {
		t.Fatalf("hostGateLogField(long) = %d bytes %q, want a capped, marked value", len(got), got[:40])
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
	startReq.Host = csrfTestHost
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
// the operator's declaration of that external hostname. The rewritten
// Host itself still has to be one of the gateway's own names to pass
// hostGate: an IP literal is, and a backend hostname is once it is
// the bind address.
func TestCSRFAllowsProxiedRequestWithRewrittenHost(t *testing.T) {
	for _, backendHost := range []string{"clawpatrol:8080", "127.0.0.1:8080", "10.0.0.7:8080"} {
		t.Run(backendHost, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			csrfBindAs(w, "clawpatrol:8080")
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

// The same proxy shape without Sec-Fetch-Site must also survive, since
// Host cannot be compared against Origin behind a proxy that rewrote
// it. The scheme is the one public_url declares.
func TestCSRFAllowsProxiedRequestWithoutSecFetchSite(t *testing.T) {
	w := newCSRFTestWebMux(t)
	csrfBindAs(w, "clawpatrol:8080")
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "clawpatrol:8080"
	req.Header.Set("Origin", "https://"+csrfTestHost)
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
	hostRefused(t, serveCSRF(w, req))
	csrfDenied(t, serveCSRFOnly(w, req))
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
			setTsnetSelf(w, "claw-gw", "")
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
			setTsnetSelf(w, "claw-gw", "")
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
	csrfBindAs(w, "backend:9090")

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

// The origin's scheme is part of it. An opposite-scheme page on the
// gateway's own name is a different origin, and on a name the operator
// declared over HTTPS a plaintext page is one an attacker astride the
// network can serve without a certificate.
func TestCSRFRejectsOppositeSchemeOnDeclaredOrigin(t *testing.T) {
	w := newCSRFTestWebMux(t)
	csrfBindAs(w, "clawpatrol:8080")
	req := csrfTestRequest(http.MethodPost, "/api/credentials/set", `{"id":"x"}`)
	req.Host = "clawpatrol:8080"
	req.Header.Set("Origin", "http://"+csrfTestHost)
	csrfDenied(t, serveCSRF(w, req))
}

// A request that arrived over TLS proves its own scheme, so a
// plaintext page on the same name cannot have initiated it.
func TestCSRFRejectsPlaintextOriginOnTLSRequest(t *testing.T) {
	w := newCSRFTestWebMux(t)
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "claw-gw.tailnet-abc.ts.net"
	setTsnetSelf(w, "claw-gw", "")
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Origin", "http://claw-gw.tailnet-abc.ts.net")
	csrfDenied(t, serveCSRF(w, req))

	ok := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	ok.Host = "claw-gw.tailnet-abc.ts.net"
	ok.TLS = &tls.ConnectionState{}
	ok.Header.Set("Origin", "https://claw-gw.tailnet-abc.ts.net")
	rr := serveCSRF(w, ok)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// A plaintext request cannot prove a scheme: it is either a plain-HTTP
// dashboard or a proxy that terminated TLS upstream, and those look
// identical from here. Both schemes are accepted on the Host half so
// the TLS-terminating proxy that preserves Host keeps working without
// public_url.
func TestCSRFAllowsEitherSchemeOnPlaintextRequest(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			w := newCSRFTestWebMux(t)
			req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
			req.Host = "localhost:8080"
			req.Header.Set("Origin", scheme+"://localhost:8080")
			rr := serveCSRF(w, req)
			csrfNotDenied(t, rr)
			if !strings.Contains(rr.Body.String(), "append_hcl is required") {
				t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
			}
		})
	}
}

// A default port is folded away, so the two spellings a browser and a
// config file may use for one origin compare equal.
func TestCSRFCanonicalOriginFoldsDefaultPorts(t *testing.T) {
	same := [][2]string{
		{csrfCanonicalOrigin("https", "gw.example:443"), "https://gw.example"},
		{csrfCanonicalOrigin("http", "gw.example:80"), "http://gw.example"},
		{csrfCanonicalOrigin("HTTPS", "GW.Example."), "https://gw.example"},
		{csrfOriginOfURL("https://gw.example:443"), "https://gw.example"},
		{csrfOriginOfURL("gw.example"), "https://gw.example"},
	}
	for _, p := range same {
		if p[0] != p[1] {
			t.Errorf("got %q, want %q", p[0], p[1])
		}
	}
	distinct := []string{
		csrfCanonicalOrigin("https", "gw.example:9999"),
		csrfCanonicalOrigin("http", "gw.example"),
		csrfCanonicalOrigin("https", "gw.example"),
	}
	for i := range distinct {
		for j := i + 1; j < len(distinct); j++ {
			if distinct[i] == distinct[j] {
				t.Errorf("%q and %q collapsed to one origin", distinct[i], distinct[j])
			}
		}
	}
	if got := csrfCanonicalOrigin("https", ""); got != "" {
		t.Errorf("empty authority yielded %q", got)
	}
	if got := csrfCanonicalOrigin("", "gw.example"); got != "" {
		t.Errorf("empty scheme yielded %q", got)
	}
}

// A public_url written with its default port must still match the
// Origin a browser serializes without one.
func TestCSRFPublicURLWithDefaultPortMatches(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.publicURL = "https://gw.example.test:443"
	w.g.cfg.Load().Settings.PublicURL = "https://gw.example.test:443"
	csrfBindAs(w, "backend:9090")
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "backend:9090"
	req.Header.Set("Origin", "https://gw.example.test")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// A hot reload that retires or replaces public_url must retire the
// origin with it. The value captured at construction is only a
// fallback for a config that carries none.
func TestCSRFLiveConfigPublicURLWinsOverCaptured(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.publicURL = "https://old.example.test"
	w.g.cfg.Load().Settings.PublicURL = "https://new.example.test"
	csrfBindAs(w, "backend:9090")

	retired := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	retired.Host = "backend:9090"
	retired.Header.Set("Origin", "https://old.example.test")
	csrfDenied(t, serveCSRF(w, retired))

	live := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	live.Host = "backend:9090"
	live.Header.Set("Origin", "https://new.example.test")
	rr := serveCSRF(w, live)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}

	// The retired hostname must also stop satisfying the Host half —
	// at the gate, and in csrfProtect's own fallback.
	byHost := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	byHost.Host = "old.example.test"
	byHost.Header.Set("Origin", "https://old.example.test")
	hostRefused(t, serveCSRF(w, byHost))
	csrfDenied(t, serveCSRFOnly(w, byHost))
}

// The captured value applies only to a mux with no config to read at
// all. Checked below the handler, since a mux without a gateway cannot
// serve a request.
func TestCSRFCapturedPublicURLUsedWhenNoConfigIsReadable(t *testing.T) {
	w := &webMux{publicURL: "https://" + csrfTestHost}
	if got := w.csrfDeclaredPublicURL(); got != "https://"+csrfTestHost {
		t.Fatalf("csrfDeclaredPublicURL = %q, want the captured value", got)
	}
	if !w.csrfHostAllowed(csrfTestHost) {
		t.Error("captured public_url host was not allowed")
	}
}

// A config that declares no public_url retires the captured one rather
// than falling back to it.
func TestCSRFEmptyLiveConfigRetiresCapturedPublicURL(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.publicURL = "https://old.example.test"
	w.g.cfg.Load().Settings.PublicURL = ""
	if got := w.csrfDeclaredPublicURL(); got != "" {
		t.Fatalf("csrfDeclaredPublicURL = %q, want empty", got)
	}
	if w.csrfHostAllowed("old.example.test") {
		t.Error("retired public_url host is still allowed")
	}
	csrfBindAs(w, "backend:9090")
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "backend:9090"
	req.Header.Set("Origin", "https://old.example.test")
	csrfDenied(t, serveCSRF(w, req))
}

// Behind a proxy that terminates TLS but preserves the external Host,
// r.TLS is nil, so the Host half would otherwise accept either scheme.
// public_url names that host and declares HTTPS, so it binds: a
// plaintext page on the name must not reach the dashboard.
func TestCSRFDeclaredSchemeBindsHostFallback(t *testing.T) {
	w := newCSRFTestWebMux(t)
	bad := csrfTestRequest(http.MethodPost, "/api/credentials/set", `{"id":"x"}`)
	bad.Host = csrfTestHost
	bad.Header.Set("Origin", "http://"+csrfTestHost)
	csrfDenied(t, serveCSRF(w, bad))

	ok := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	ok.Host = csrfTestHost
	ok.Header.Set("Origin", "https://"+csrfTestHost)
	rr := serveCSRF(w, ok)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// The declared scheme binds the host, not the port: a dashboard also
// reachable on another port of the declared host keeps working.
func TestCSRFDeclaredSchemeDoesNotPinThePort(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.g.cfg.Load().Settings.PublicURL = "https://" + csrfTestHost + ":8443"
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = csrfTestHost + ":9000"
	req.Header.Set("Origin", "https://"+csrfTestHost+":9000")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// A host with no declared origin keeps both schemes, so the
// TLS-terminating proxy that preserves Host works without public_url.
func TestCSRFUndeclaredHostKeepsBothSchemes(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.publicURL = ""
	w.g.cfg.Load().Settings.PublicURL = ""
	w.g.cfg.Load().Settings.DashboardListen = "dash.internal:8080"
	for _, scheme := range []string{"http", "https"} {
		req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
		req.Host = "dash.internal:8080"
		req.Header.Set("Origin", scheme+"://dash.internal:8080")
		rr := serveCSRF(w, req)
		csrfNotDenied(t, rr)
		if !strings.Contains(rr.Body.String(), "append_hcl is required") {
			t.Fatalf("%s: body = %q, want the config handler's own answer", scheme, rr.Body.String())
		}
	}
}

// An IPv6 literal is bracketed in an origin whether or not a port
// follows, so the two spellings of one origin must compare equal.
func TestCSRFCanonicalOriginBracketsIPv6(t *testing.T) {
	pairs := [][2]string{
		{csrfCanonicalOrigin("https", "[::1]:443"), "https://[::1]"},
		{csrfCanonicalOrigin("https", "[::1]"), "https://[::1]"},
		{csrfCanonicalOrigin("http", "[::1]:80"), "http://[::1]"},
		{csrfCanonicalOrigin("https", "[fd00::5]:9000"), "https://[fd00::5]:9000"},
		{csrfOriginOfURL("https://[::1]:443"), "https://[::1]"},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			t.Errorf("got %q, want %q", p[0], p[1])
		}
	}
	if got := csrfHostOfOrigin("https://[fd00::5]:9000"); got != "[fd00::5]" {
		t.Errorf("csrfHostOfOrigin = %q, want %q", got, "[fd00::5]")
	}
	if got := csrfHostOfOrigin("https://gw.example:9000"); got != "gw.example" {
		t.Errorf("csrfHostOfOrigin = %q, want %q", got, "gw.example")
	}
}

// An IPv6 public_url written with its default port must match the
// bracketed, port-less Origin a browser serializes.
func TestCSRFPublicURLIPv6DefaultPortMatches(t *testing.T) {
	w := newCSRFTestWebMux(t)
	w.g.cfg.Load().Settings.PublicURL = "https://[::1]:443"
	csrfBindAs(w, "backend:9090")
	req := csrfTestRequest(http.MethodPost, "/api/config/apply", `{}`)
	req.Host = "backend:9090"
	req.Header.Set("Origin", "https://[::1]")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if !strings.Contains(rr.Body.String(), "append_hcl is required") {
		t.Fatalf("body = %q, want the config handler's own answer", rr.Body.String())
	}
}

// The login form's POST sets the root password on a gateway that has
// none, so a cross-site submission would choose the operator's password
// for them. SameSite=Lax is no help: first-run setup presents no cookie
// to withhold.
func TestCSRFProtectsLoginPost(t *testing.T) {
	w := newCSRFTestWebMux(t)
	if got := w.authRequirementForPath(dashboardLoginPath); got != authPublic {
		t.Fatalf("authRequirementForPath(%q) = %v, want authPublic", dashboardLoginPath, got)
	}

	body := "password=" + authTestRootPassword + "&confirm=" + authTestRootPassword
	crossSite := httptest.NewRequest(http.MethodPost, dashboardLoginPath, strings.NewReader(body))
	crossSite.Host = csrfTestHost
	crossSite.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	csrfDenied(t, serveCSRF(w, crossSite))

	foreign := httptest.NewRequest(http.MethodPost, dashboardLoginPath, strings.NewReader(body))
	foreign.Host = csrfTestHost
	foreign.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	foreign.Header.Set("Origin", "https://evil.example")
	csrfDenied(t, serveCSRF(w, foreign))
}

// The dashboard's own login form must still submit, and the form itself
// must still render for a caller with no credential at all.
func TestCSRFAllowsSameSiteLoginPostAndPublicGET(t *testing.T) {
	w := newCSRFTestWebMux(t)
	body := "password=" + authTestRootPassword
	req := httptest.NewRequest(http.MethodPost, dashboardLoginPath+"?next=/", strings.NewReader(body))
	req.Host = csrfTestHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+csrfTestHost)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rr := serveCSRF(w, req)
	csrfNotDenied(t, rr)
	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want %d; body = %q", rr.Code, http.StatusFound, rr.Body.String())
	}

	// A cross-site navigation to the form still renders it, as long as
	// it addresses the gateway by one of its own names.
	get := httptest.NewRequest(http.MethodGet, dashboardLoginPath, nil)
	get.Host = csrfTestHost
	get.Header.Set("Sec-Fetch-Site", "cross-site")
	grr := serveCSRF(w, get)
	csrfNotDenied(t, grr)
	if grr.Code != http.StatusOK {
		t.Fatalf("login GET status = %d, want %d", grr.Code, http.StatusOK)
	}
}

// /api/tailscale/connect starts a login and holds a tunnel open past
// the response. A GET may not do that: the origin check deliberately
// lets GETs through, because a GET is not supposed to change anything.
func TestTailscaleConnectRejectsNonPOST(t *testing.T) {
	w := newCSRFTestWebMux(t)
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		req := csrfTestRequest(method, "/api/tailscale/connect?id=nope", "")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Origin", "https://"+csrfTestHost)
		rr := serveCSRF(w, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want %d; body = %q", method, rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
		}
	}
}

// The GET-only status endpoint stays a reader: it reports a parked
// login URL, and rejects any method that could be mistaken for the
// acquiring one.
func TestTailscaleStatusReportsParkedURLAndRejectsNonGET(t *testing.T) {
	const credName = "status-cred"
	defer tailscaleproto.Default.Set(credName, "")
	tailscaleproto.Default.Set(credName, "https://login.tailscale.example/a/parked")

	w := newCSRFTestWebMux(t)
	w.g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{credName: {
			Plugin: &config.Plugin{Type: "tailscale_credential"},
			Body:   stubTailscaleCred{},
		}},
	})

	req := csrfTestRequest(http.MethodGet, "/api/tailscale/status?id="+credName, "")
	rr := serveCSRF(w, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp tailscaleAuthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.PendingURL != "https://login.tailscale.example/a/parked" {
		t.Fatalf("PendingURL = %q, want the parked URL", resp.PendingURL)
	}
	if resp.Status != "pending" {
		t.Fatalf("Status = %q, want pending", resp.Status)
	}

	bad := csrfTestRequest(http.MethodPost, "/api/tailscale/status?id="+credName, "")
	bad.Header.Set("Sec-Fetch-Site", "same-origin")
	bad.Header.Set("Origin", "https://"+csrfTestHost)
	if brr := serveCSRF(w, bad); brr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want %d", brr.Code, http.StatusMethodNotAllowed)
	}
}
