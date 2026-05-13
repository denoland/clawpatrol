package credentials

// google_gke_credential: the kubernetes endpoint plugin runs
// `gcloud container clusters get-credentials` / `gcloud auth
// print-access-token` (via gke-gcloud-auth-plugin) at request time
// using these parameters and uses the resulting bearer as the
// Authorization header. Configured via ADC / workload identity at
// the cluster level — no paste-secret slots, no env pushdown.

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

// GoogleGKECredential is part of the clawpatrol plugin API.
type GoogleGKECredential struct {
	Cluster                   string `hcl:"cluster"`
	Location                  string `hcl:"location"`
	Project                   string `hcl:"project"`
	ImpersonateServiceAccount string `hcl:"impersonate_service_account,optional"`
}

func init() {
	config.Register(&config.Plugin{
		Kind:  config.KindCredential,
		Type:  "google_gke_credential",
		New:   newer[GoogleGKECredential](),
		Build: passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*GoogleGKECredential)
			b.SetAttributeValue("cluster", cty.StringVal(v.Cluster))
			b.SetAttributeValue("location", cty.StringVal(v.Location))
			b.SetAttributeValue("project", cty.StringVal(v.Project))
			if v.ImpersonateServiceAccount != "" {
				b.SetAttributeValue("impersonate_service_account", cty.StringVal(v.ImpersonateServiceAccount))
			}
		},
	})
}
