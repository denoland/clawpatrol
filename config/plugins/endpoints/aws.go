package endpoints

// aws endpoint: a single AWS service host (e.g. dynamodb.us-east-1.amazonaws.com)
// paired with the service + region SigV4 needs at sign time. The
// credential is an aws_credential; the endpoint exists so service +
// region travel with the deployment, not with the operator's access
// key. One endpoint per (service, region) pair — agents typically
// only call a handful of AWS services per upstream, so the schema
// stays straight-line.

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

// AWSEndpoint is part of the clawpatrol plugin API.
type AWSEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Service    string   `hcl:"service"`
	Region     string   `hcl:"region"`
	Credential string   `hcl:"credential,optional"`
}

// EndpointHosts is part of the clawpatrol plugin API.
func (e *AWSEndpoint) EndpointHosts() []string { return e.Hosts }

// EndpointCredentials is part of the clawpatrol plugin API.
func (e *AWSEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

// AWSSigningParams is the contract the aws_credential plugin reads at
// request time. Kept narrow so a future hand-rolled SigV4 endpoint
// variant (presigned URL minter, S3-style virtual-host) can satisfy
// the same shape without leaking AWSEndpoint internals.
func (e *AWSEndpoint) AWSSigningParams() (service, region string) {
	return e.Service, e.Region
}

func init() {
	config.Register(&config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   "aws",
		Family: "http",
		New:    func() any { return &AWSEndpoint{} },
		Refs:   singularRef,
		Build:  passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*AWSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			b.SetAttributeValue("service", cty.StringVal(e.Service))
			b.SetAttributeValue("region", cty.StringVal(e.Region))
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}
