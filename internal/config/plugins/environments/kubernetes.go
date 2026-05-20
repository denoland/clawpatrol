package environments

// kubernetes_environment: writes a `KUBECONFIG` env var pointing at
// the kubeconfig the operator already maintains for clawpatrol. The
// value is a literal path that the operator sets (defaults to
// $HOME/.kube/clawpatrol-<name>) — the gateway can't materialize
// the kubeconfig itself from inside `clawpatrol env` because the
// file lives on the agent box, not the gateway. The point of this
// plugin is to make the path opt-in per-profile so two profiles
// with access to different clusters can each point at their own
// config.
//
// Sample HCL:
//
//	endpoint "kubernetes" "k8s-dev" { server = "198.51.100.10" }
//
//	credential "mtls_credential" "k8s-dev-mtls" {
//	  endpoint = kubernetes.k8s-dev
//	}
//
//	environment "kubernetes_environment" "k8s-dev-env" {
//	  endpoint   = kubernetes.k8s-dev
//	  credential = mtls_credential.k8s-dev-mtls
//	  kubeconfig = "/home/agent/.kube/clawpatrol-dev"
//	}
//
//	profile "alice" {
//	  credentials  = [mtls_credential.k8s-dev-mtls]
//	  environments = [kubernetes_environment.k8s-dev-env]
//	}

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
)

// KubernetesEnvironment is part of the clawpatrol plugin API.
type KubernetesEnvironment struct {
	Kubeconfig string `hcl:"kubeconfig" json:"kubeconfig"`
}

// EnvVars is part of the clawpatrol plugin API.
func (k *KubernetesEnvironment) EnvVars() []config.EnvVar {
	if k == nil || k.Kubeconfig == "" {
		return nil
	}
	return []config.EnvVar{
		{Name: "KUBECONFIG", Value: k.Kubeconfig, Description: "path to the kubeconfig pointing at the clawpatrol endpoint"},
	}
}

func kubernetesValidate(decoded any, name string, _ *config.BuildCtx) hcl.Diagnostics {
	k, ok := decoded.(*KubernetesEnvironment)
	if !ok {
		return nil
	}
	if k.Kubeconfig == "" {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("environment %q: kubernetes_environment requires `kubeconfig = \"<path>\"`", name),
		}}
	}
	return nil
}

func kubernetesEmit(body any, _ string, b *hclwrite.Body) {
	k, ok := body.(*KubernetesEnvironment)
	if !ok {
		return
	}
	if k.Kubeconfig != "" {
		b.SetAttributeValue("kubeconfig", cty.StringVal(k.Kubeconfig))
	}
}

func init() {
	var _ config.EnvironmentRuntime = (*KubernetesEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:     config.KindEnvironment,
		Type:     "kubernetes_environment",
		New:      newer[KubernetesEnvironment](),
		Validate: kubernetesValidate,
		Build:    passthrough,
		Emit:     kubernetesEmit,
	})
}
