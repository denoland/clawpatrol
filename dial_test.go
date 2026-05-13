package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
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

func endpointWithTunnelAndTLSCredential(name string, tunnel *config.CompiledTunnel, credential *fakeTLSCredential) *config.CompiledEndpoint {
	return &config.CompiledEndpoint{
		Name:   name,
		Tunnel: tunnel,
		Credentials: []*config.CompiledCredential{{
			Credential: &config.Entity{
				Symbol: &config.Symbol{Name: "mtls"},
				Body:   credential,
			},
		}},
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
