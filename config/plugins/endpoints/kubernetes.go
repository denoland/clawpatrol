package endpoints

// kubernetes endpoint: self-hosted clusters (server + ca_cert) and
// managed clusters (hosts + EKS-style credential resolved at request
// time).

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

type KubernetesEndpoint struct {
	Hosts       []string `hcl:"hosts,optional"`
	Server      string   `hcl:"server,optional"`
	CACert      string   `hcl:"ca_cert,optional"`
	Description string   `hcl:"description,optional"`
	Credential  string   `hcl:"credential,optional"`
}

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

func (e *KubernetesEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
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
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}
