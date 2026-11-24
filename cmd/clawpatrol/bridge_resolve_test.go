package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBridgeHostMapSet(t *testing.T) {
	var m bridgeHostMap
	for _, v := range []string{
		"clawpatrol-api.clawpatrol.svc=10.96.100.10",
		"Gateway.Example.COM.=fd00::10",
		"wg.example.com=::ffff:192.0.2.1",
	} {
		if err := m.Set(v); err != nil {
			t.Fatalf("Set(%q) = %v", v, err)
		}
	}
	want := map[string]string{
		"clawpatrol-api.clawpatrol.svc": "10.96.100.10",
		"gateway.example.com":           "fd00::10",
		"wg.example.com":                "192.0.2.1",
	}
	if len(m) != len(want) {
		t.Fatalf("map = %v, want %v", m, want)
	}
	for host, ip := range want {
		if got := m[host]; got != netip.MustParseAddr(ip) {
			t.Errorf("m[%q] = %v, want %s", host, got, ip)
		}
	}
	if got := m.String(); got != "clawpatrol-api.clawpatrol.svc=10.96.100.10,gateway.example.com=fd00::10,wg.example.com=192.0.2.1" {
		t.Errorf("String() = %q", got)
	}

	for _, bad := range []string{
		"",
		"gateway.example.com",
		"=10.0.0.1",
		"gateway.example.com:8080=10.0.0.1",
		"10.0.0.2=10.0.0.1",
		"[fd00::1]=10.0.0.1",
		"bad..name=10.0.0.1",
		"-bad.example.com=10.0.0.1",
		"bad name=10.0.0.1",
		"gateway.example.com=",
		"gateway.example.com=gateway",
		"gateway.example.com=[fd00::1]",
		"gateway.example.com=10.0.0.1:8080",
		"clawpatrol-api.clawpatrol.svc=10.96.100.11",
		"CLAWPATROL-API.clawpatrol.svc.=10.96.100.11",
	} {
		err := m.Set(bad)
		if err == nil {
			t.Errorf("Set(%q) expected error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "--resolve "+strconv.Quote(bad)) {
			t.Errorf("Set(%q) error %q does not name the flag value", bad, err)
		}
	}
}

// failingResolver fails every lookup and counts the attempts.
func failingResolver(calls *int) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			*calls++
			return nil, errors.New("DNS is not available")
		},
	}
}

func withBridgeHosts(t *testing.T, m bridgeHostMap, resolver *net.Resolver) {
	t.Helper()
	prevHosts, prevResolver := bridgeStaticHosts, bridgeResolver
	t.Cleanup(func() { bridgeStaticHosts, bridgeResolver = prevHosts, prevResolver })
	bridgeStaticHosts = newBridgeHosts(m)
	bridgeResolver = resolver
}

func TestLookupHostIPsUsesResolveEntries(t *testing.T) {
	var m bridgeHostMap
	for _, v := range []string{"clawpatrol-api.clawpatrol.svc=10.96.100.10", "wg.example.com=fd00::10"} {
		if err := m.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	var calls int
	withBridgeHosts(t, m, failingResolver(&calls))
	captureLog(t)

	for host, want := range map[string]string{
		"clawpatrol-api.clawpatrol.svc":  "10.96.100.10",
		"CLAWPATROL-API.Clawpatrol.svc.": "10.96.100.10",
		"wg.example.com":                 "fd00::10",
		"192.0.2.7":                      "192.0.2.7",
	} {
		ips, err := lookupHostIPs(host)
		if err != nil {
			t.Fatalf("lookupHostIPs(%q) = %v", host, err)
		}
		if len(ips) != 1 || ips[0] != netip.MustParseAddr(want) {
			t.Fatalf("lookupHostIPs(%q) = %v, want [%s]", host, ips, want)
		}
	}
	if calls != 0 {
		t.Fatalf("mapped names used the resolver %d times", calls)
	}

	if _, err := lookupHostIPs("other.example.com"); err == nil {
		t.Fatal("unmapped name resolved without DNS")
	}
	if calls == 0 {
		t.Fatal("unmapped name did not use the resolver")
	}
}

func TestBridgeHostsLogsDNSOncePerName(t *testing.T) {
	var calls int
	resolver := failingResolver(&calls)

	t.Run("with entries", func(t *testing.T) {
		var m bridgeHostMap
		if err := m.Set("gateway.example.com=10.0.0.1"); err != nil {
			t.Fatal(err)
		}
		withBridgeHosts(t, m, resolver)
		buf := captureLog(t)
		for _, host := range []string{"gateway.example.com", "wg.example.com", "WG.example.com.", "wg.example.com", "other.example.com", "192.0.2.1"} {
			_, _ = lookupHostIPs(host)
		}
		got := buf.String()
		for host, want := range map[string]int{"wg.example.com": 1, "other.example.com": 1, "gateway.example.com": 0, "192.0.2.1": 0} {
			if n := strings.Count(got, "resolving "+host+" through DNS"); n != want {
				t.Errorf("DNS log lines for %s = %d, want %d; log:\n%s", host, n, want, got)
			}
		}
	})

	t.Run("without entries", func(t *testing.T) {
		withBridgeHosts(t, nil, resolver)
		buf := captureLog(t)
		_, _ = lookupHostIPs("wg.example.com")
		if strings.Contains(buf.String(), "through DNS") {
			t.Fatalf("logged DNS use without --resolve entries:\n%s", buf)
		}
	})
}

// A mapped host dials its entry. TLS SNI, certificate verification, and the
// Host header keep the name from the URL.
func TestBridgeHostsDialKeepsURLHost(t *testing.T) {
	const name = "gateway.clawpatrol.test"
	cert, pool := selfSignedCert(t, name)

	var gotSNI, gotHost string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSNI, gotHost = r.TLS.ServerName, r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	var m bridgeHostMap
	if err := m.Set(name + "=127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	hosts := newBridgeHosts(m)
	var dialed []string
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: hosts.dialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return dialer.DialContext(ctx, network, addr)
		}),
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	u := url.URL{Scheme: "https", Host: net.JoinHostPort(name, strconv.Itoa(port)), Path: "/"}
	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("GET %s: %v", u.String(), err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotSNI != name {
		t.Errorf("server SNI = %q, want %q", gotSNI, name)
	}
	if gotHost != u.Host {
		t.Errorf("server Host = %q, want %q", gotHost, u.Host)
	}
	if want := []string{"127.0.0.1:" + strconv.Itoa(port)}; len(dialed) != 1 || dialed[0] != want[0] {
		t.Errorf("dialed %v, want %v", dialed, want)
	}
}

// selfSignedCert returns a certificate for name only (no IP SANs) and a pool
// that trusts it.
func selfSignedCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
