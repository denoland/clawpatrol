package endpoints

import (
	"crypto/tls"
	"strings"
	"testing"
)

// TestKubernetesEndpointConfigureUpstreamTLS verifies the endpoint's
// ca_cert HCL field is applied to cfg.RootCAs at dial time. Without
// this wiring the EKS apiserver path errors with "x509: certificate
// signed by unknown authority" because EKS uses a per-cluster CA
// that no system trust store carries.
func TestKubernetesEndpointConfigureUpstreamTLS(t *testing.T) {
	// Real self-signed ed25519 cert (generated once with `openssl req`),
	// included verbatim so the test stays hermetic.
	const ca = `-----BEGIN CERTIFICATE-----
MIIBTzCCAQGgAwIBAgIUIFiZ5s2fC7N/ElT4ljred+5VuZYwBQYDK2VwMB0xGzAZ
BgNVBAMMEmNsYXdwYXRyb2wtdGVzdC1jYTAeFw0yNjA1MTMyMjM2MDdaFw0zNjA1
MTAyMjM2MDdaMB0xGzAZBgNVBAMMEmNsYXdwYXRyb2wtdGVzdC1jYTAqMAUGAytl
cAMhAEEjAD+PAfsebOa0TpxGWC4BbXTJZS0Zyio+ag4KjFuMo1MwUTAdBgNVHQ4E
FgQUyuf5UybO1z6734KuSwqtX94QnmQwHwYDVR0jBBgwFoAUyuf5UybO1z6734Ku
SwqtX94QnmQwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQA4uIgKBvkbVsXIoitq
DpvHwDcxnGIz9Te9sfFH29Zr2iHwmMcz5T34iFfm/7XpBw8ajzrO+i5nFfIofiAI
bRYL
-----END CERTIFICATE-----`
	e := &KubernetesEndpoint{CACert: ca}
	cfg := &tls.Config{}
	if err := e.ConfigureUpstreamTLS(cfg); err != nil {
		t.Fatalf("ConfigureUpstreamTLS: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil after ConfigureUpstreamTLS — ca_cert was ignored")
	}
	if got := len(cfg.RootCAs.Subjects()); got == 0 { //nolint:staticcheck // SA1019 fine for test
		t.Fatal("RootCAs has no certificates after ConfigureUpstreamTLS")
	}
}

// TestKubernetesEndpointConfigureUpstreamTLSEmpty verifies the
// no-op path: endpoints that don't declare a ca_cert leave cfg
// untouched so the credential's ConfigureUpstreamTLS (mtls) or the
// system trust store still wins.
func TestKubernetesEndpointConfigureUpstreamTLSEmpty(t *testing.T) {
	e := &KubernetesEndpoint{}
	cfg := &tls.Config{}
	if err := e.ConfigureUpstreamTLS(cfg); err != nil {
		t.Fatalf("ConfigureUpstreamTLS: %v", err)
	}
	if cfg.RootCAs != nil {
		t.Fatal("RootCAs mutated even though ca_cert was empty")
	}
}

// TestKubernetesEndpointConfigureUpstreamTLSBadPEM surfaces a
// configuration error when ca_cert isn't decodable. Operators see
// the error at dial time (logged + fallback to default roots).
func TestKubernetesEndpointConfigureUpstreamTLSBadPEM(t *testing.T) {
	e := &KubernetesEndpoint{CACert: "not a pem"}
	cfg := &tls.Config{}
	err := e.ConfigureUpstreamTLS(cfg)
	if err == nil {
		t.Fatal("expected error on un-decodable ca_cert")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("err = %v, want one mentioning PEM", err)
	}
}
