package credentials

// aws_eks_credential: the kubernetes endpoint plugin runs
// `aws eks get-token` at request time using these parameters and uses
// the resulting bearer as the Authorization header. Configured via
// mTLS / IAM at the cluster level — no paste-secret slots, no env
// pushdown.

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

type AWSEKSCredential struct {
	Cluster string `hcl:"cluster"`
	Region  string `hcl:"region"`
	Profile string `hcl:"profile,optional"`
}

func init() {
	config.Register(&config.Plugin{
		Kind:  config.KindCredential,
		Type:  "aws_eks_credential",
		New:   newer[AWSEKSCredential](),
		Build: passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*AWSEKSCredential)
			b.SetAttributeValue("cluster", cty.StringVal(v.Cluster))
			b.SetAttributeValue("region", cty.StringVal(v.Region))
			if v.Profile != "" {
				b.SetAttributeValue("profile", cty.StringVal(v.Profile))
			}
		},
	})
}
