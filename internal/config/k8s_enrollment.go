package config

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// K8sDefaultProfileLabel is the Pod label a kubernetes_token_review match
// reads the clawpatrol profile from when `profile_label` is omitted.
const K8sDefaultProfileLabel = "clawpatrol.dev/profile"

// k8sEnrollmentType is the enrollment plugin type label.
const k8sEnrollmentType = "kubernetes_token_review"

// K8sEnrollment is the built (canonical) form of a
// `enrollment "kubernetes_token_review" "<name>" { ... }` block. It is
// what the plugin's Build returns and what the runtime and emit paths
// read; the plugin compile hook lowers it into a CompiledK8sEnrollment
// carried by the generic CompiledEnrollment envelope.
type K8sEnrollment struct {
	Audience string     `json:"audience"`
	Matches  []K8sMatch `json:"match"`
	// KeepaliveInterval is the raw time.ParseDuration string for the
	// WireGuard persistent-keepalive interval, empty when omitted (defaults
	// to EnrollmentDefaultKeepalive). KeepaliveReapCount is the missed-
	// keepalive count before an enrolled peer is reaped, nil when omitted
	// (defaults to EnrollmentDefaultReapCount); 0 disables reaping. The
	// liveness window is derived (keepalive × reap count), never set directly.
	KeepaliveInterval  string `json:"keepalive_interval,omitempty"`
	KeepaliveReapCount *int   `json:"keepalive_reap_count,omitempty"`
}

// K8sMatch is one identity → profile-binding rule. A Pod is matched on
// namespace + service_account; its profile is then read from the Pod
// label named by ProfileLabel and must appear in Profiles.
type K8sMatch struct {
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	ProfileLabel   string   `json:"profile_label"`
	Profiles       []string `json:"profiles"`
}

// k8sEnrollmentBody is the body of an `enrollment
// "kubernetes_token_review" "<name>"` block. It authorizes Kubernetes
// workloads to self-enroll as transient WireGuard peers by verifying a
// projected ServiceAccount token with the Kubernetes TokenReview API.
type k8sEnrollmentBody struct {
	// Audience is passed to Kubernetes TokenReview and must match the
	// projected ServiceAccount token's audience. Required.
	Audience string `hcl:"audience"`
	// Matches are the repeated `match { ... }` rules. Each binds one
	// namespace + service_account identity to a profile allowlist. At
	// least one is required.
	Matches []k8sMatchBody `hcl:"match,block"`
	// KeepaliveInterval is the WireGuard persistent-keepalive interval
	// (time.ParseDuration) the sidecar applies to enrolled peers and pushed to
	// it at enroll. Optional; defaults to 25s and must be at least 10s (the
	// floor is pinned to the gateway reaper's sample cadence). There is no
	// upper bound: a longer interval just means fewer keepalive packets and a
	// longer liveness window (keepalive_interval × keepalive_reap_count).
	KeepaliveInterval string `hcl:"keepalive_interval,optional"`
	// KeepaliveReapCount is how many missed keepalives elapse before an
	// enrolled peer is reaped; the liveness window is keepalive_interval ×
	// keepalive_reap_count. Expressing it as a count keeps the safety ratio
	// an integer that can't be misconfigured. Optional; defaults to 3. Set to
	// 0 to disable reaping (and the sidecar's self-heal escalation) entirely;
	// any other value must be 2 or greater.
	KeepaliveReapCount *int `hcl:"keepalive_reap_count,optional"`
}

// k8sMatchBody is one identity → profile-binding rule inside a
// kubernetes_token_review enrollment.
type k8sMatchBody struct {
	// Namespace the pod must run in. Required.
	Namespace string `hcl:"namespace"`
	// ServiceAccount the pod's token must belong to. Required.
	ServiceAccount string `hcl:"service_account"`
	// ProfileLabel is the Pod label the clawpatrol profile is read from.
	// Optional; defaults to "clawpatrol.dev/profile".
	ProfileLabel string `hcl:"profile_label,optional"`
	// Profiles is the allowlist of profiles a matched pod may bind. The
	// value of the profile_label pod label must appear here. Required
	// (at least one), and each must be a declared `profile "<name>"`.
	Profiles []string `hcl:"profiles"`
}

func init() {
	Register(&Plugin{
		Kind:              KindEnrollment,
		Type:              k8sEnrollmentType,
		New:               func() any { return new(k8sEnrollmentBody) },
		Validate:          validateK8sEnrollment,
		Build:             buildK8sEnrollment,
		CompileEnrollment: compileK8sEnrollment,
		Emit:              emitK8sEnrollment,
	})
}

func validateK8sEnrollment(decoded any, name string, ctx *BuildCtx) hcl.Diagnostics {
	body := decoded.(*k8sEnrollmentBody)
	var diags hcl.Diagnostics

	if strings.TrimSpace(body.Audience) == "" {
		diags = append(diags, enrollmentDiag(ctx, "Missing enrollment audience",
			fmt.Sprintf("enrollment %q requires `audience` so projected ServiceAccount tokens are scoped to clawpatrol.", name)))
	}
	if len(body.Matches) == 0 {
		diags = append(diags, enrollmentDiag(ctx, "Missing enrollment match",
			fmt.Sprintf("enrollment %q requires at least one `match { namespace = ..., service_account = ..., profiles = [...] }` block.", name)))
	}
	for i, m := range body.Matches {
		if strings.TrimSpace(m.Namespace) == "" {
			diags = append(diags, enrollmentDiag(ctx, "Invalid enrollment match",
				fmt.Sprintf("enrollment %q match[%d] is missing `namespace`.", name, i)))
		}
		if strings.TrimSpace(m.ServiceAccount) == "" {
			diags = append(diags, enrollmentDiag(ctx, "Invalid enrollment match",
				fmt.Sprintf("enrollment %q match[%d] is missing `service_account`.", name, i)))
		}
		if len(m.Profiles) == 0 {
			diags = append(diags, enrollmentDiag(ctx, "Invalid enrollment match",
				fmt.Sprintf("enrollment %q match[%d] is missing at least one profile.", name, i)))
		}
		for j, prof := range m.Profiles {
			if strings.TrimSpace(prof) == "" {
				diags = append(diags, enrollmentDiag(ctx, "Invalid enrollment match",
					fmt.Sprintf("enrollment %q match[%d].profiles[%d] is empty.", name, i, j)))
				continue
			}
			// Each listed profile must resolve to a declared
			// `profile "<name>"` — resolved through the symbol table like
			// the OIDC enrollment plugin resolves its target profile.
			if ctx != nil && ctx.Symbols != nil && ctx.Symbols.Get(KindProfile, prof) == nil {
				diags = append(diags, enrollmentDiag(ctx, "Unknown enrollment profile",
					fmt.Sprintf("enrollment %q match[%d] targets profile %q which is not declared.", name, i, prof)))
			}
		}
	}

	diags = append(diags, validateEnrollmentKeepaliveInterval(ctx, name, body.KeepaliveInterval)...)
	diags = append(diags, validateEnrollmentReapCount(ctx, name, body.KeepaliveReapCount)...)
	return diags
}

func buildK8sEnrollment(decoded any, _ string, _ *BuildCtx) (any, hcl.Diagnostics) {
	body := decoded.(*k8sEnrollmentBody)
	out := &K8sEnrollment{
		Audience:           body.Audience,
		KeepaliveInterval:  body.KeepaliveInterval,
		KeepaliveReapCount: body.KeepaliveReapCount,
	}
	for _, m := range body.Matches {
		label := strings.TrimSpace(m.ProfileLabel)
		if label == "" {
			label = K8sDefaultProfileLabel
		}
		out.Matches = append(out.Matches, K8sMatch{
			Namespace:      m.Namespace,
			ServiceAccount: m.ServiceAccount,
			ProfileLabel:   label,
			Profiles:       append([]string(nil), m.Profiles...),
		})
	}
	return out, nil
}

func emitK8sEnrollment(body any, _ string, b *hclwrite.Body) {
	ke := body.(*K8sEnrollment)
	b.SetAttributeValue("audience", cty.StringVal(ke.Audience))
	for _, m := range ke.Matches {
		mb := b.AppendNewBlock("match", nil).Body()
		mb.SetAttributeValue("namespace", cty.StringVal(m.Namespace))
		mb.SetAttributeValue("service_account", cty.StringVal(m.ServiceAccount))
		if m.ProfileLabel != "" {
			mb.SetAttributeValue("profile_label", cty.StringVal(m.ProfileLabel))
		}
		mb.SetAttributeValue("profiles", StringListVal(m.Profiles))
	}
	if ke.KeepaliveInterval != "" {
		b.SetAttributeValue("keepalive_interval", cty.StringVal(ke.KeepaliveInterval))
	}
	if ke.KeepaliveReapCount != nil {
		b.SetAttributeValue("keepalive_reap_count", cty.NumberIntVal(int64(*ke.KeepaliveReapCount)))
	}
}

// validateEnrollmentGateway enforces the cross-block invariant that
// workload enrollment provisions WireGuard peers, so a `wireguard { ... }`
// data-plane block must be declared whenever any enrollment is configured.
// Mirrors how the OIDC enrollment plugin validates gateway-level
// preconditions after per-block decode.
func validateEnrollmentGateway(gw *Gateway) hcl.Diagnostics {
	if gw == nil || gw.Policy == nil || len(gw.Policy.Enrollments) == 0 {
		return nil
	}
	if gw.Settings == nil || gw.Settings.WireGuard == nil {
		return hcl.Diagnostics{&hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "enrollment requires a wireguard block",
			Detail:   "`enrollment` provisions WireGuard peers; declare a `wireguard { ... }` block for the data plane.",
		}}
	}
	return nil
}
