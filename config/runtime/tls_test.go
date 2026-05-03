package runtime_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	_ "github.com/denoland/clawpatrol-go/config/plugins/all"
	"github.com/denoland/clawpatrol-go/config/plugins/credentials"
	"github.com/denoland/clawpatrol-go/config/runtime"
)

// TestMTLSConfigure round-trips a freshly-generated cert / key / CA
// through the mtls_credential's ConfigureUpstreamTLS hook and asserts
// the resulting tls.Config has Certificates + RootCAs populated.
func TestMTLSConfigure(t *testing.T) {
	certPEM, keyPEM, caPEM := genTestPEMs(t)
	sec := runtime.Secret{
		Extras: map[string]string{
			"cert": string(certPEM),
			"key":  string(keyPEM),
			"ca":   string(caPEM),
		},
	}
	m := &credentials.MTLSCredential{}
	cfg := &tls.Config{}
	if err := m.ConfigureUpstreamTLS(cfg, sec); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates len=%d, want 1", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Errorf("RootCAs not populated")
	}
}

func TestMTLSMissingCert(t *testing.T) {
	m := &credentials.MTLSCredential{}
	if err := m.ConfigureUpstreamTLS(&tls.Config{}, runtime.Secret{}); err == nil {
		t.Errorf("expected error for empty secret")
	}
}

func genTestPEMs(t *testing.T) (cert, key, ca []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	key = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	ca = cert // self-signed: the cert IS its own CA bundle
	return
}
