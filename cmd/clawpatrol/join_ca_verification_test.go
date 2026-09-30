package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything written to it. The join flow reports the CA fingerprint on
// stdout, which is the only place an operator can read it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prev := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			sb.Write(buf[:n])
			if rerr != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	os.Stdout = prev
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// sandboxJoinHostState points the per-user state a join would write at temp
// directories, so a test can never reach a developer's real daemon credential
// or shell rc.
func sandboxJoinHostState(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
}

// stopAfterCAGate makes caDir read-only, so a device flow that gets past the CA
// gate aborts at its next mandatory write — the mode marker — instead of
// running real platform setup. That setup is not what these cases are about and
// is not safe to run from a test: on Linux it writes a daemon auth-key, and on
// macOS it hands the poll-delivered auth key to the installed helper app, which
// reconfigures the live tunnel.
// Root ignores the mode bits (CAP_DAC_OVERRIDE), so the flow would run that
// setup for real; a test that relies on this stopping the flow is skipped
// there rather than left to fail misleadingly.
func stopAfterCAGate(t *testing.T, caDir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only dir this case relies on to stop the flow")
	}
	if err := os.Chmod(caDir, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", caDir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(caDir, 0o700) })
}

// deviceFlowCAServer is a gateway stub for the device-flow join: it serves a
// CA at /ca.crt and delivers a possibly different one inline in the approval
// poll, which is how a tsnet-mode gateway hands over its CA.
type deviceFlowCAServer struct {
	server     *httptest.Server
	publicCA   []byte // served at /ca.crt ("" ⇒ 404, as a tsnet gateway does)
	polledCA   []byte // delivered as ca_pem in the poll response
	loginSrv   string // "" ⇒ tsnet join; "wireguard://wg0" ⇒ WireGuard join
	pollCalled bool
}

func newDeviceFlowCAServer(t *testing.T, s *deviceFlowCAServer) *deviceFlowCAServer {
	t.Helper()
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ca.crt":
			if len(s.publicCA) == 0 {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(s.publicCA)
		case "/api/onboard/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "device-code",
				"user_code":   "USER-CODE",
				// Tailnet-only so the flow renders a QR instead of
				// launching a browser mid-test.
				"verify_url": "http://100.64.0.1/approve",
				"interval":   -1,
				"expires_in": 60,
			})
		case "/api/onboard/poll":
			s.pollCalled = true
			_ = json.NewEncoder(w).Encode(map[string]string{
				"auth_key":     "tskey-auth-test",
				"login_server": s.loginSrv,
				"control_url":  "https://controlplane.example.test",
				"gateway_host": "gw.example.ts.net",
				"gateway_ip":   "100.64.0.9",
				"ca_pem":       string(s.polledCA),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

// TestDeviceFlowRejectsTamperedPollDeliveredCA is the path production takes:
// a tsnet-mode gateway defers its CA to the approval poll, and the join defers
// the trust install to commitApprovedCA. A poll that answers with a CA other
// than the one staged from /ca.crt is an on-path substitution, and the join has
// to refuse it rather than write it and hand it to the system trust store.
func TestDeviceFlowRejectsTamperedPollDeliveredCA(t *testing.T) {
	realCA, _, _ := mintCA(t, "gateway-real", 1)
	attackerCA, _, _ := mintCA(t, "attacker", 2)
	h := newDeviceFlowCAServer(t, &deviceFlowCAServer{
		publicCA: realCA,
		polledCA: attackerCA,
	})
	installed := recordInstalls(t)
	caDir := t.TempDir()

	setup, err := preJoinFetchCA(h.server.URL, caDir, "", h.server.Client())
	if err != nil {
		t.Fatalf("preJoinFetchCA: %v", err)
	}

	var flowErr error
	_ = captureStdout(t, func() {
		_, flowErr = onboardViaDeviceFlow(h.server.URL, false, "", "device-flow-test",
			&setup, false, h.server.Client(), false)
	})
	if flowErr == nil {
		t.Fatal("a poll-delivered CA that differs from the staged one must abort the join")
	}
	if !strings.Contains(flowErr.Error(), "does not match") {
		t.Errorf("error must name the fingerprint mismatch, got %v", flowErr)
	}
	if !h.pollCalled {
		t.Error("the flow must have reached the approval poll")
	}
	if len(*installed) != 0 {
		t.Errorf("a substituted CA must never reach the trust store, got %d installs", len(*installed))
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err == nil {
		t.Error("a substituted CA must not be written to ca.crt")
	}
}

// TestDeviceFlowAcceptsMatchingPollDeliveredCA is the other half of the gate:
// a gateway that delivers the same CA it serves at /ca.crt must get past the
// fingerprint check. The platform setup that follows is not exercised here, so
// the assertion is that whatever ends the flow, it is not the CA check.
func TestDeviceFlowAcceptsMatchingPollDeliveredCA(t *testing.T) {
	realCA, _, _ := mintCA(t, "gateway-real", 1)
	h := newDeviceFlowCAServer(t, &deviceFlowCAServer{
		publicCA: realCA,
		polledCA: realCA,
	})
	sandboxJoinHostState(t)
	recordInstalls(t)
	caDir := t.TempDir()

	setup, err := preJoinFetchCA(h.server.URL, caDir, "", h.server.Client())
	if err != nil {
		t.Fatalf("preJoinFetchCA: %v", err)
	}
	stopAfterCAGate(t, caDir)

	var flowErr error
	_ = captureStdout(t, func() {
		_, flowErr = onboardViaDeviceFlow(h.server.URL, false, "", "device-flow-test",
			&setup, false, h.server.Client(), false)
	})
	if flowErr != nil && strings.Contains(flowErr.Error(), "does not match") {
		t.Errorf("a matching CA must pass the fingerprint check, got %v", flowErr)
	}
	// Past the gate, the flow reaches the first write into the now read-only
	// dir. Anything else means it stopped somewhere unintended.
	if flowErr == nil || !strings.Contains(flowErr.Error(), "write mode") {
		t.Errorf("want the flow to reach the mode-marker write, got %v", flowErr)
	}
}

// TestDeviceFlowPrintsPollDeliveredCAFingerprint covers the operator's side of
// the tsnet path. The CA rides the approval poll, so its fingerprint cannot be
// printed before the approval click; printing it when it arrives is what gives
// the fingerprint the dashboard displays something to be compared against.
//
// Both shapes that can authenticate a poll-delivered CA are covered, because
// the print is what the operator reads in either one.
func TestDeviceFlowPrintsPollDeliveredCAFingerprint(t *testing.T) {
	polledCA, _, _ := mintCA(t, "gateway-real", 1)
	wantFP, err := caFingerprintFromPEM(polledCA)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("staged-ca", func(t *testing.T) {
		// The gateway also serves /ca.crt, so the poll-delivered copy is held
		// against the staged fingerprint.
		h := newDeviceFlowCAServer(t, &deviceFlowCAServer{
			publicCA: polledCA,
			polledCA: polledCA,
		})
		assertPrintsCAFingerprint(t, h, "", wantFP)
	})

	t.Run("pinned-no-public-ca", func(t *testing.T) {
		// A tsnet-mode gateway exposes /ca.crt only over the tailnet, so a
		// public-Funnel join sees no staged CA and the pin is what authenticates
		// the one the poll delivers.
		h := newDeviceFlowCAServer(t, &deviceFlowCAServer{polledCA: polledCA})
		assertPrintsCAFingerprint(t, h, wantFP, wantFP)
	})
}

// assertPrintsCAFingerprint drives the device flow against h and requires the
// CA fingerprint to appear on stdout in the form the dashboard tells the
// operator to look for.
func assertPrintsCAFingerprint(t *testing.T, h *deviceFlowCAServer, pin, wantFP string) {
	t.Helper()
	sandboxJoinHostState(t)
	recordInstalls(t)
	caDir := t.TempDir()

	setup, err := preJoinFetchCA(h.server.URL, caDir, pin, h.server.Client())
	if err != nil && !isCaNotExposed(err) {
		t.Fatalf("preJoinFetchCA: %v", err)
	}
	stopAfterCAGate(t, caDir)

	out := captureStdout(t, func() {
		_, _ = onboardViaDeviceFlow(h.server.URL, false, "", "device-flow-test",
			&setup, false, h.server.Client(), false)
	})
	if !strings.Contains(out, "CA fingerprint: "+wantFP) {
		t.Errorf("the poll-delivered CA's fingerprint must be printed for comparison\nwant %q in:\n%s",
			"CA fingerprint: "+wantFP, out)
	}
}

// TestCaFingerprintPinRejectsSubstituteCA covers --ca-fingerprint on the
// pre-join fetch: a pinned join must refuse a CA the pin does not cover instead
// of staging it as the candidate the rest of the flow works from.
func TestCaFingerprintPinRejectsSubstituteCA(t *testing.T) {
	realCA, _, _ := mintCA(t, "gateway-real", 1)
	attackerCA, _, _ := mintCA(t, "attacker", 2)
	realFP, err := caFingerprintFromPEM(realCA)
	if err != nil {
		t.Fatal(err)
	}
	h := newDeviceFlowCAServer(t, &deviceFlowCAServer{publicCA: attackerCA})
	caDir := t.TempDir()

	setup, err := preJoinFetchCA(h.server.URL, caDir, realFP, h.server.Client())
	if err == nil {
		t.Fatal("a CA that does not match --ca-fingerprint must abort the join")
	}
	if !strings.Contains(err.Error(), "--ca-fingerprint") {
		t.Errorf("error must name the pin, got %v", err)
	}
	if len(setup.candidateCA) != 0 {
		t.Error("a CA that fails the pin must not be staged as the candidate")
	}

	// The matching CA passes, so the pin gates substitution rather than
	// blocking every pinned join.
	h2 := newDeviceFlowCAServer(t, &deviceFlowCAServer{publicCA: realCA})
	ok, err := preJoinFetchCA(h2.server.URL, t.TempDir(), realFP, h2.server.Client())
	if err != nil {
		t.Fatalf("a CA matching the pin must be accepted: %v", err)
	}
	if len(ok.candidateCA) == 0 {
		t.Error("a CA matching the pin must be staged")
	}
}

// TestCaFingerprintPinRejectsTamperedPollDeliveredCA is the pin on the tsnet
// path, where the gateway exposes no public /ca.crt and the pin is therefore
// the only thing standing between a substituted CA and the system trust store.
func TestCaFingerprintPinRejectsTamperedPollDeliveredCA(t *testing.T) {
	realCA, _, _ := mintCA(t, "gateway-real", 1)
	attackerCA, _, _ := mintCA(t, "attacker", 2)
	realFP, err := caFingerprintFromPEM(realCA)
	if err != nil {
		t.Fatal(err)
	}
	h := newDeviceFlowCAServer(t, &deviceFlowCAServer{polledCA: attackerCA})
	installed := recordInstalls(t)
	caDir := t.TempDir()

	setup, err := preJoinFetchCA(h.server.URL, caDir, realFP, h.server.Client())
	if err != nil && !isCaNotExposed(err) {
		t.Fatalf("preJoinFetchCA: %v", err)
	}
	if setup.pinnedCAFP != realFP {
		t.Fatalf("the pin must survive a deferred CA fetch, got %q", setup.pinnedCAFP)
	}

	var flowErr error
	_ = captureStdout(t, func() {
		_, flowErr = onboardViaDeviceFlow(h.server.URL, false, "", "device-flow-test",
			&setup, false, h.server.Client(), false)
	})
	if flowErr == nil || !strings.Contains(flowErr.Error(), "--ca-fingerprint") {
		t.Fatalf("a poll-delivered CA outside the pin must abort the join, got %v", flowErr)
	}
	if len(*installed) != 0 {
		t.Errorf("a substituted CA must never reach the trust store, got %d installs", len(*installed))
	}
}

// TestCommitApprovedCAKeepsStagedFingerprint pins the reason the fingerprint
// check is load-bearing: the staged fingerprint is the reference value, so
// commitApprovedCA must not overwrite it with the candidate's own fingerprint.
// Doing so would reduce every later comparison to a value against itself.
func TestCommitApprovedCAKeepsStagedFingerprint(t *testing.T) {
	staged, _, _ := mintCA(t, "gateway-real", 1)
	substitute, _, _ := mintCA(t, "attacker", 2)
	stagedFP, err := caFingerprintFromPEM(staged)
	if err != nil {
		t.Fatal(err)
	}
	installed := recordInstalls(t)
	dir := t.TempDir()

	s := &joinSetup{caPath: filepath.Join(dir, "ca.crt"), caFingerprint: stagedFP}
	if err := s.commitApprovedCA(substitute, false); err == nil {
		t.Fatal("committing a CA outside the staged fingerprint must fail")
	}
	if s.caFingerprint != stagedFP {
		t.Errorf("the staged fingerprint is the reference value and must survive a commit attempt, got %q", s.caFingerprint)
	}
	if len(*installed) != 0 {
		t.Errorf("a rejected commit must install nothing, got %d installs", len(*installed))
	}
	if _, err := os.Stat(s.caPath); err == nil {
		t.Error("a rejected commit must not write ca.crt")
	}

	// The staged CA itself still commits.
	if err := s.commitApprovedCA(staged, false); err != nil {
		t.Fatalf("committing the staged CA must succeed: %v", err)
	}
	if len(*installed) != 1 {
		t.Fatalf("the approved CA must be installed, got %d installs", len(*installed))
	}
}

// TestNormalizeCAFingerprint covers the shapes an operator can paste a pin in.
func TestNormalizeCAFingerprint(t *testing.T) {
	ca, _, _ := mintCA(t, "gateway", 1)
	canonical, err := caFingerprintFromPEM(ca)
	if err != nil {
		t.Fatal(err)
	}
	bare := strings.ReplaceAll(canonical, ":", "")
	for _, in := range []string{
		canonical,
		strings.ToLower(canonical),
		bare,
		strings.ToLower(bare),
		"sha256:" + canonical,
		"  " + canonical + "  ",
	} {
		got, err := normalizeCAFingerprint(in)
		if err != nil {
			t.Errorf("normalizeCAFingerprint(%q): %v", in, err)
			continue
		}
		if got != canonical {
			t.Errorf("normalizeCAFingerprint(%q) = %q, want %q", in, got, canonical)
		}
	}
	for _, bad := range []string{
		"",
		"not-hex",
		bare[:len(bare)-2],       // too short
		bare + "AB",              // too long
		strings.Repeat("zz", 32), // right length, not hex
	} {
		if got, err := normalizeCAFingerprint(bad); err == nil {
			t.Errorf("normalizeCAFingerprint(%q) = %q, want an error", bad, got)
		}
	}
}

// TestJoinTLSVerifiedPolicy states where the join authenticates the gateway's
// own certificate. A publicly-rooted host — including the *.ts.net name a
// Funnel gateway answers on, which is where production joins land — is
// verified; only the shapes no public root can match are waived.
func TestJoinTLSVerifiedPolicy(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		// Funnel URL: Tailscale terminates :443 with a Let's Encrypt cert.
		{"https://clawpatrol-gateway.tail9a48e.ts.net", true},
		{"https://clawpatrol-gateway.tail9a48e.ts.net/ca.crt", true},
		// A gateway behind an operator-supplied public domain.
		{"https://clawpatrol-gateway.example.com", true},
		{"HTTPS://Clawpatrol-Gateway.Example.Com", true},
		// No TLS to verify.
		{"http://clawpatrol-gateway.tail9a48e.ts.net:8080", false},
		{"http://100.79.206.14:8080", false},
		// IP literals: a tsnet listener holds no certificate for an address.
		{"https://100.79.206.14", false},
		{"https://127.0.0.1:8443", false},
		{"https://[::1]:8443", false},
		// Loopback names reach a TLS port whose leaf the gateway's own CA mints.
		{"https://localhost:8443", false},
		// A fully qualified name naming the same host, root dot and all.
		{"https://localhost.:8443", false},
		{"https://gw.localhost.:8443", false},
		{"https://clawpatrol-gateway.example.com.", true},
		{"https://LOCALHOST:8443", false},
		{"https://gw.localhost:8443", false},
		// A URL that cannot be classified keeps verification on: the waiver
		// has to be earned. None of these is dialable anyway.
		{"", true},
		{"://nope", true},
		{"not-a-url", true},
	}
	for _, tc := range cases {
		if got := joinTLSVerified(tc.url); got != tc.want {
			t.Errorf("joinTLSVerified(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// TestJoinHTTPClientVerifiesNamedHTTPSGateway is the behavioural half of the
// policy: the client the join builds for a publicly-rooted gateway must
// actually reject a certificate the public roots do not sign, and the client it
// builds for an IP literal must still connect — that gateway's TLS port answers
// with a leaf minted by the very CA the join has not fetched yet.
func TestJoinHTTPClientVerifiesNamedHTTPSGateway(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	// Point a named gateway URL at the test server without touching DNS, so
	// the only thing deciding the outcome is the client's TLS config.
	dialToTestServer := func(cli *http.Client) {
		tr, ok := cli.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("join client transport is %T, want *http.Transport", cli.Transport)
		}
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
	}

	named := newJoinHTTPClient("https://clawpatrol-gateway.example.com", 10*time.Second)
	dialToTestServer(named)
	if resp, err := named.Get("https://clawpatrol-gateway.example.com/ca.crt"); err == nil {
		_ = resp.Body.Close()
		t.Error("a named https gateway must have its certificate verified")
	} else {
		var verr *tls.CertificateVerificationError
		if !errors.As(err, &verr) {
			t.Errorf("want a certificate verification failure, got %v", err)
		}
	}

	literal := newJoinHTTPClient("https://127.0.0.1:8443", 10*time.Second)
	dialToTestServer(literal)
	resp, err := literal.Get("https://127.0.0.1:8443/ca.crt")
	if err != nil {
		t.Fatalf("an IP-literal gateway must stay reachable without verification: %v", err)
	}
	_ = resp.Body.Close()
}

// TestDeviceFlowRefusesUnauthenticatedPollDeliveredCA closes the case where
// nothing could vouch for a poll-delivered CA: the gateway served no /ca.crt to
// stage a fingerprint from, the operator gave no pin, and the transport carries
// a certificate no public root signs. Trusting the CA there would rest on
// nothing at all, so the join has to stop and say what is missing.
func TestDeviceFlowRefusesUnauthenticatedPollDeliveredCA(t *testing.T) {
	polledCA, _, _ := mintCA(t, "whoever-answered", 1)
	h := newDeviceFlowCAServer(t, &deviceFlowCAServer{polledCA: polledCA})
	sandboxJoinHostState(t)
	installed := recordInstalls(t)
	caDir := t.TempDir()

	// httptest serves over http://127.0.0.1, so the transport is unverified and
	// no /ca.crt is exposed — exactly the combination under test.
	setup, err := preJoinFetchCA(h.server.URL, caDir, "", h.server.Client())
	if err != nil && !isCaNotExposed(err) {
		t.Fatalf("preJoinFetchCA: %v", err)
	}
	if setup.caFingerprint != "" || setup.pinnedCAFP != "" {
		t.Fatal("this case requires both reference fingerprints to be absent")
	}
	if joinTLSVerified(h.server.URL) {
		t.Fatal("this case requires an unverified transport")
	}

	var flowErr error
	_ = captureStdout(t, func() {
		_, flowErr = onboardViaDeviceFlow(h.server.URL, false, "", "device-flow-test",
			&setup, false, h.server.Client(), false)
	})
	if flowErr == nil || !strings.Contains(flowErr.Error(), "nothing authenticates it") {
		t.Fatalf("an unauthenticated CA must abort the join, got %v", flowErr)
	}
	if !strings.Contains(flowErr.Error(), "--ca-fingerprint") {
		t.Error("the error must tell the operator how to proceed")
	}
	if len(*installed) != 0 {
		t.Errorf("nothing may be installed, got %d installs", len(*installed))
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err == nil {
		t.Error("no ca.crt may be written")
	}
}

// TestFetchCAHTTPExplainsCertificateRejection keeps the verified path's failure
// actionable: a gateway whose certificate no public root signs must say so and
// name the tailnet URL, not surface a bare TLS error.
func TestFetchCAHTTPExplainsCertificateRejection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("unreachable"))
	}))
	defer srv.Close()

	// A named https gateway is verified, so the test server's own certificate
	// is rejected; dial straight at it so no DNS is involved.
	cli := newJoinHTTPClient("https://gateway.internal", 10*time.Second)
	tr, ok := cli.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("join client transport is %T, want *http.Transport", cli.Transport)
	}
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}

	_, _, err := fetchCAHTTP("https://gateway.internal", cli)
	if err == nil {
		t.Fatal("a certificate no public root signs must be rejected")
	}
	for _, want := range []string{"no public root signs", "tailnet URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %q, got %v", want, err)
		}
	}
}

// TestJoinTransportAuthenticatedRequiresPositiveClassification is the other
// direction of the same classification: crediting the transport with
// authenticating a CA is a positive claim, so only a publicly-rooted https host
// earns it. Both decisions therefore fail closed on a URL neither can read —
// verification stays on, and no CA rides in unchecked on an unknown transport.
func TestJoinTransportAuthenticatedRequiresPositiveClassification(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://clawpatrol-gateway.tail9a48e.ts.net", true},
		{"https://clawpatrol-gateway.example.com.", true},
		// No TLS, or TLS nothing public can vouch for.
		{"http://clawpatrol-gateway.tail9a48e.ts.net:8080", false},
		{"https://100.79.206.14", false},
		{"https://127.0.0.1:8443", false},
		{"https://localhost:8443", false},
		{"https://gw.localhost.:8443", false},
		// Unclassifiable: no authentication may be claimed.
		{"", false},
		{"://nope", false},
		{"not-a-url", false},
		{"ftp://gateway.example.com", false},
	}
	for _, tc := range cases {
		if got := joinTransportAuthenticated(tc.url); got != tc.want {
			t.Errorf("joinTransportAuthenticated(%q) = %v, want %v", tc.url, got, tc.want)
		}
		// The two predicates may never both be true: a transport cannot be
		// authenticated and have its verification waived at the same time.
		if joinTransportAuthenticated(tc.url) && !joinTLSVerified(tc.url) {
			t.Errorf("%q is claimed authenticated while verification is waived", tc.url)
		}
	}
}

// TestJoinClientRefusesOffOriginRedirect closes the gap between judging a URL
// and trusting what comes back over it. The transport decisions read the
// gateway URL the operator named, so the exchange has to stay on that origin: a
// redirect to another host — or from https down to plain http — would deliver
// the CA over a transport nothing authenticated, while the flow still credited
// the origin it started from.
func TestJoinClientRefusesOffOriginRedirect(t *testing.T) {
	ca, _, _ := mintCA(t, "gateway", 1)

	t.Run("cross-origin-is-refused", func(t *testing.T) {
		elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("attacker CA"))
		}))
		defer elsewhere.Close()
		gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/ca.crt", http.StatusFound)
		}))
		defer gw.Close()

		_, _, err := fetchCAHTTP(gw.URL, newJoinHTTPClient(gw.URL, 10*time.Second))
		if err == nil {
			t.Fatal("a redirect off the gateway's origin must not be followed")
		}
		if !strings.Contains(err.Error(), "off the gateway's origin") {
			t.Errorf("error must name the refused redirect, got %v", err)
		}
	})

	t.Run("same-origin-is-followed", func(t *testing.T) {
		// A gateway may legitimately redirect within its own origin, and that
		// stays on the transport the join judged.
		gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ca.crt" {
				http.Redirect(w, r, "/real-ca.crt", http.StatusFound)
				return
			}
			_, _ = w.Write(ca)
		}))
		defer gw.Close()

		got, _, err := fetchCAHTTP(gw.URL, newJoinHTTPClient(gw.URL, 10*time.Second))
		if err != nil {
			t.Fatalf("a same-origin redirect must be followed: %v", err)
		}
		if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(ca)) {
			t.Error("the CA from the redirect target must be returned")
		}
	})

	t.Run("tls-downgrade-is-refused", func(t *testing.T) {
		// Scheme is part of the origin, so https → http is refused on the same
		// host. Checked directly: it is the shape an on-path attacker would
		// want, and it needs no live TLS server to state.
		req := &http.Request{URL: &neturl.URL{Scheme: "http", Host: "gw.example.com"}}
		via := []*http.Request{{URL: &neturl.URL{Scheme: "https", Host: "gw.example.com"}}}
		if err := refuseOffOriginRedirect(req, via); err == nil {
			t.Error("an https → http redirect must be refused")
		}
	})
}
