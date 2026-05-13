package endpoints

// kubernetes endpoint: self-hosted clusters (server + ca_cert) and
// managed clusters (hosts + EKS-style credential resolved at request
// time).

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

// KubernetesEndpoint is part of the clawpatrol plugin API.
//
// ClusterName + Region are EKS auth parameters: when the bound
// credential is `aws_credential`, the gateway presigns an STS
// GetCallerIdentity URL scoped to (region, cluster_name) and stamps
// the result as a `k8s-aws-v1.<…>` bearer. Leave both unset for
// self-hosted clusters with a non-EKS credential (bearer_token,
// mtls_credential).
type KubernetesEndpoint struct {
	Hosts       []string `hcl:"hosts,optional"`
	Server      string   `hcl:"server,optional"`
	CACert      string   `hcl:"ca_cert,optional"`
	Description string   `hcl:"description,optional"`
	ClusterName string   `hcl:"cluster_name,optional"`
	Region      string   `hcl:"region,optional"`
	Credential  string   `hcl:"credential,optional"`
}

// EndpointHosts is part of the clawpatrol plugin API.
func (e *KubernetesEndpoint) EndpointHosts() []string {
	if len(e.Hosts) > 0 {
		return e.Hosts
	}
	if e.Server != "" {
		return []string{e.Server}
	}
	return nil
}

// FileIncludeFields tells the loader to inline `<<file:NAME>>` markers
// in ca_cert. Self-hosted clusters reference the cluster CA via
// filename so cert material stays out of the policy file.
func (e *KubernetesEndpoint) FileIncludeFields() []config.FileIncludeField {
	return []config.FileIncludeField{
		{Get: func() string { return e.CACert }, Set: func(v string) { e.CACert = v }},
	}
}

// EndpointCredentials is part of the clawpatrol plugin API.
func (e *KubernetesEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

// AWSEKSAuthParams is the contract the aws_credential plugin reads at
// request time to mint an EKS bearer token. Kept narrow so a future
// alternative k8s-on-AWS endpoint (e.g. one that wraps a different
// auth flow) can satisfy the same shape without leaking
// KubernetesEndpoint internals.
func (e *KubernetesEndpoint) AWSEKSAuthParams() (cluster, region string) {
	return e.ClusterName, e.Region
}

// ConfigureUpstreamTLS pins cfg.RootCAs to the cluster CA when the
// endpoint declares one. EKS apiservers present a per-cluster CA
// that the system trust store can't validate; the operator inlines
// it via `ca_cert = <<file:cluster-ca.pem>>` (or the base64 from
// `aws eks describe-cluster`). Self-hosted clusters whose
// mtls_credential already supplies a `ca` slot leave this empty —
// the credential's ConfigureUpstreamTLS runs next and wins.
func (e *KubernetesEndpoint) ConfigureUpstreamTLS(cfg *tls.Config) error {
	if e.CACert == "" {
		return nil
	}
	pool := cfg.RootCAs
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(e.CACert)) {
		return errors.New("kubernetes endpoint ca_cert: no PEM blocks parsed")
	}
	cfg.RootCAs = pool
	return nil
}

func init() {
	config.Register(&config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   "kubernetes",
		Family: "k8s",
		New:    func() any { return &KubernetesEndpoint{} },
		Refs:   singularRef,
		Build:  passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*KubernetesEndpoint)
			if len(e.Hosts) > 0 {
				b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			}
			if e.Server != "" {
				b.SetAttributeValue("server", cty.StringVal(e.Server))
			}
			if e.CACert != "" {
				b.SetAttributeValue("ca_cert", cty.StringVal(e.CACert))
			}
			if e.Description != "" {
				b.SetAttributeValue("description", cty.StringVal(e.Description))
			}
			if e.ClusterName != "" {
				b.SetAttributeValue("cluster_name", cty.StringVal(e.ClusterName))
			}
			if e.Region != "" {
				b.SetAttributeValue("region", cty.StringVal(e.Region))
			}
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}
