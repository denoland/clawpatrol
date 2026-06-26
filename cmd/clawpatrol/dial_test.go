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
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type fakeTLSCredential struct {
	configured atomic.Int32
}

func (c *fakeTLSCredential) ConfigureUpstreamTLS(_ *tls.Config, _ runtime.Secret) error {
	c.configured.Add(1)
	return nil
}

type fakeSecretStore struct{}

func (fakeSecretStore) Get(string) (runtime.Secret, error) {
	return runtime.Secret{}, nil
}

type fakeEndpointTLSConfigurer struct {
	configured atomic.Int32
	rootCAs    *x509.CertPool
}

func (c *fakeEndpointTLSConfigurer) ConfigureUpstreamTLS(cfg *tls.Config) error {
	c.configured.Add(1)
	cfg.RootCAs = c.rootCAs
	return nil
}

func endpointWithTunnelAndTLSCredential(name string, tunnel *config.CompiledTunnel, credential *fakeTLSCredential) *config.CompiledEndpoint {
	return &config.CompiledEndpoint{
		Name:   name,
		Tunnel: tunnel,
		Credentials: []*config.Entity{{
			Symbol: &config.Symbol{Name: "mtls"},
			Body:   credential,
		}},
	}
}

func TestBrowserTLSUsesEndpointTLSConfig(t *testing.T) {
	server, roots, serverName := newSelfSignedTLSServer(t)
	defer server.Close()

	tlsConfig := &fakeEndpointTLSConfigurer{rootCAs: roots}
	ep := &config.CompiledEndpoint{Name: "browser", Body: tlsConfig}
	g := &Gateway{dialer: &net.Dialer{}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := g.dialBrowserTLS(ctx, "tcp", server.Listener.Addr().String(), serverName, ep)
	if err != nil {
		t.Fatalf("dialBrowserTLS: %v", err)
	}
	_ = conn.Close()
	if got := tlsConfig.configured.Load(); got != 1 {
		t.Fatalf("EndpointTLSConfigurer call count = %d, want 1", got)
	}
}

func TestTransportBrowserTLSUsesEndpointTunnel(t *testing.T) {
	oldHosts := browserTLSHosts
	browserTLSHosts = []string{"browser.invalid"}
	t.Cleanup(func() { browserTLSHosts = oldHosts })

	sentinel := errors.New("fake tunnel dial used")
	ct, fake := makeCompiledTunnel("egress", runtime.TunnelShareSingleton, 0, false, nil)
	fake.dialErr = sentinel
	ep := &config.CompiledEndpoint{Name: "browser", Tunnel: ct}
	g := &Gateway{
		dialer:  &net.Dialer{},
		tunnels: NewTunnelManager(runtime.EnvSecretStore{}, ""),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := g.transportFor(ep).DialTLSContext(ctx, "tcp", "browser.invalid:443")
	if !errors.Is(err, sentinel) {
		t.Fatalf("DialTLSContext error = %v, want fake tunnel sentinel", err)
	}
	if got := fake.dialCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Dial count = %d, want 1", got)
	}
	if fake.dialAddr != "browser.invalid:443" {
		t.Fatalf("fake tunnel Dial addr = %q, want browser.invalid:443", fake.dialAddr)
	}
}

func TestDialWSUpstreamBrowserTLSUsesEndpointTunnel(t *testing.T) {
	sentinel := errors.New("fake tunnel dial used")
	ct, fake := makeCompiledTunnel("egress", runtime.TunnelShareSingleton, 0, false, nil)
	fake.dialErr = sentinel
	ep := &config.CompiledEndpoint{Name: "browser-ws", Tunnel: ct}
	g := &Gateway{
		dialer:  &net.Dialer{},
		tunnels: NewTunnelManager(runtime.EnvSecretStore{}, ""),
	}

	_, err := g.dialWSUpstream(context.Background(), "browser.invalid", ep, "")
	if !errors.Is(err, sentinel) {
		t.Fatalf("dialWSUpstream error = %v, want fake tunnel sentinel", err)
	}
	if got := fake.dialCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Dial count = %d, want 1", got)
	}
	if fake.dialAddr != "browser.invalid:443" {
		t.Fatalf("fake tunnel Dial addr = %q, want browser.invalid:443", fake.dialAddr)
	}
}

func TestBrowserTLSHandshakeFailureReleasesTunnel(t *testing.T) {
	ct, fake := makeCompiledTunnel("egress", runtime.TunnelShareSingleton, 0, false, nil)
	fake.closePeerOnDial = true
	ep := &config.CompiledEndpoint{Name: "browser", Tunnel: ct}
	g := &Gateway{
		dialer:  &net.Dialer{},
		tunnels: NewTunnelManager(runtime.EnvSecretStore{}, ""),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := g.dialBrowserTLS(ctx, "tcp", "browser.invalid:443", "browser.invalid", ep)
	if err == nil {
		t.Fatal("dialBrowserTLS succeeded, want handshake error")
	}
	if got := fake.dialCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Dial count = %d, want 1", got)
	}
	if got := fake.closeCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Close count = %d, want 1", got)
	}
}

func TestBrowserTLSDialErrorReleasesTunnel(t *testing.T) {
	sentinel := errors.New("fake tunnel dial failed")
	ct, fake := makeCompiledTunnel("egress", runtime.TunnelShareSingleton, 0, false, nil)
	fake.dialErr = sentinel
	ep := &config.CompiledEndpoint{Name: "browser", Tunnel: ct}
	g := &Gateway{
		dialer:  &net.Dialer{},
		tunnels: NewTunnelManager(runtime.EnvSecretStore{}, ""),
	}

	_, err := g.dialBrowserTLS(context.Background(), "tcp", "browser.invalid:443", "browser.invalid", ep)
	if !errors.Is(err, sentinel) {
		t.Fatalf("dialBrowserTLS error = %v, want fake tunnel sentinel", err)
	}
	if got := fake.dialCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Dial count = %d, want 1", got)
	}
	if got := fake.closeCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Close count = %d, want 1", got)
	}
}

func TestTransportBrowserTLSWithClientCertUsesDialUpstream(t *testing.T) {
	oldHosts := browserTLSHosts
	browserTLSHosts = []string{"browser.invalid"}
	t.Cleanup(func() { browserTLSHosts = oldHosts })

	sentinel := errors.New("fake tunnel dial used")
	ct, fake := makeCompiledTunnel("egress", runtime.TunnelShareSingleton, 0, false, nil)
	fake.dialErr = sentinel
	credential := &fakeTLSCredential{}
	ep := endpointWithTunnelAndTLSCredential("browser-mtls", ct, credential)
	g := &Gateway{
		dialer:  &net.Dialer{},
		tunnels: NewTunnelManager(runtime.EnvSecretStore{}, ""),
		secrets: fakeSecretStore{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := g.transportFor(ep).DialTLSContext(ctx, "tcp", "browser.invalid:443")
	if !errors.Is(err, sentinel) {
		t.Fatalf("DialTLSContext error = %v, want fake tunnel sentinel", err)
	}
	if got := credential.configured.Load(); got != 1 {
		t.Fatalf("TLS credential configured count = %d, want 1", got)
	}
	if got := fake.dialCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Dial count = %d, want 1", got)
	}
}

func newSelfSignedTLSServer(t *testing.T) (*httptest.Server, *x509.CertPool, string) {
	t.Helper()

	serverName := "kubernetes.test"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	server.StartTLS()
	return server, roots, serverName
}

func TestDialWSUpstreamWithClientCertUsesDialUpstream(t *testing.T) {
	sentinel := errors.New("fake tunnel dial used")
	ct, fake := makeCompiledTunnel("egress", runtime.TunnelShareSingleton, 0, false, nil)
	fake.dialErr = sentinel
	credential := &fakeTLSCredential{}
	ep := endpointWithTunnelAndTLSCredential("browser-ws-mtls", ct, credential)
	g := &Gateway{
		dialer:  &net.Dialer{},
		tunnels: NewTunnelManager(runtime.EnvSecretStore{}, ""),
		secrets: fakeSecretStore{},
	}

	_, err := g.dialWSUpstream(context.Background(), "browser.invalid", ep, "")
	if !errors.Is(err, sentinel) {
		t.Fatalf("dialWSUpstream error = %v, want fake tunnel sentinel", err)
	}
	if got := credential.configured.Load(); got != 1 {
		t.Fatalf("TLS credential configured count = %d, want 1", got)
	}
	if got := fake.dialCount.Load(); got != 1 {
		t.Fatalf("fake tunnel Dial count = %d, want 1", got)
	}
}
