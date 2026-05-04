package credentials

// mtls_credential: client cert + key (+ optional CA bundle) for
// mTLS-authenticated upstreams (k8s API servers, internal CAs).
// Configures the upstream tls.Config rather than stamping a header.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type MTLSCredential struct{}

func (m *MTLSCredential) ConfigureUpstreamTLS(cfg *tls.Config, sec runtime.Secret) error {
	certPEM := []byte(sec.Extras["cert"])
	keyPEM := []byte(sec.Extras["key"])
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return errors.New("mtls credential missing cert / key (set CLAWPATROL_SECRET_<NAME>_CERT and _KEY)")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("mtls keypair: %w", err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	if caPEM := []byte(sec.Extras["ca"]); len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return errors.New("mtls ca bundle: no PEM blocks parsed")
		}
		cfg.RootCAs = pool
	}
	return nil
}

func (*MTLSCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "cert", Label: "Client cert (PEM)", Multiline: true},
		{Name: "key", Label: "Client key (PEM)", Multiline: true},
		{Name: "ca", Label: "CA bundle (PEM, optional)", Multiline: true,
			Description: "Leave empty to use system roots."},
	}
}

func init() {
	var _ runtime.TLSCredentialRuntime = (*MTLSCredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "mtls_credential",
		New:     newer[MTLSCredential](),
		Runtime: (*MTLSCredential)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
