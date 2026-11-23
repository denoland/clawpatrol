package config

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
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
	// TunnelSplitCIDRs is the raw tunnel_split_cidrs list.
	TunnelSplitCIDRs []string `json:"tunnel_split_cidrs,omitempty"`
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
	// TunnelSplitCIDRs are ranges, such as the Pod and Service ranges, that
	// the bridge routes through the Pod's original default gateway instead of
	// the tunnel. The list adds routes; it does not limit the routes the CNI
	// installs. It is not an enforcement control: use NetworkPolicy.
	TunnelSplitCIDRs []string `hcl:"tunnel_split_cidrs,optional"`
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
	if _, err := ParseTunnelSplitCIDRs(body.TunnelSplitCIDRs); err != nil {
		diags = append(diags, enrollmentDiag(ctx, "Invalid enrollment tunnel_split_cidrs",
			fmt.Sprintf("enrollment %q tunnel_split_cidrs: %v", name, err)))
	}
	return diags
}

func buildK8sEnrollment(decoded any, _ string, _ *BuildCtx) (any, hcl.Diagnostics) {
	body := decoded.(*k8sEnrollmentBody)
	out := &K8sEnrollment{
		Audience:           body.Audience,
		KeepaliveInterval:  body.KeepaliveInterval,
		KeepaliveReapCount: body.KeepaliveReapCount,
		TunnelSplitCIDRs:   body.TunnelSplitCIDRs,
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
	if len(ke.TunnelSplitCIDRs) > 0 {
		b.SetAttributeValue("tunnel_split_cidrs", StringListVal(ke.TunnelSplitCIDRs))
	}
}

// ParseTunnelSplitCIDRs parses and masks tunnel_split_cidrs entries and
// drops duplicates. A /0 is rejected because the tunnel must stay the default
// route.
func ParseTunnelSplitCIDRs(raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR", s)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("%q covers every address; the tunnel must stay the default route", s)
		}
		if p = p.Masked(); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// WireGuardIPv6Subnet is the IPv6 range of the tunnel addresses derived from
// the IPv4 subnet: fd77:: plus the subnet's host bits, and always at least
// the last octet (see wgHostMask and wg6FromV4 in cmd/clawpatrol).
func WireGuardIPv6Subnet(subnet netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0x77}), 96+min(subnet.Bits(), 24))
}

// validateTunnelSplitCIDRs rejects tunnel_split_cidrs entries that
// overlap the WireGuard tunnel ranges.
func validateTunnelSplitCIDRs(gw *Gateway) hcl.Diagnostics {
	subnet, err := netip.ParsePrefix(gw.Settings.WireGuard.SubnetCIDR)
	if err != nil {
		return nil // validateOperational reports it
	}
	tunnel := []netip.Prefix{subnet.Masked(), WireGuardIPv6Subnet(subnet)}
	var diags hcl.Diagnostics
	for _, name := range slices.Sorted(maps.Keys(gw.Policy.Enrollments)) {
		ke, ok := gw.Policy.Enrollments[name].Body.(*K8sEnrollment)
		if !ok {
			continue
		}
		cidrs, err := ParseTunnelSplitCIDRs(ke.TunnelSplitCIDRs)
		if err != nil {
			continue // validateK8sEnrollment reports it
		}
		for _, c := range cidrs {
			if i := slices.IndexFunc(tunnel, c.Overlaps); i >= 0 {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Invalid enrollment tunnel_split_cidrs",
					Detail: fmt.Sprintf("enrollment %q: %s overlaps the WireGuard subnet %s; tunnel traffic would leave through the CNI.",
						name, c, tunnel[i]),
				})
			}
		}
	}
	return diags
}

// validateEnrollmentGateway enforces the cross-block invariants of workload
// enrollment: it provisions WireGuard peers, so a `wireguard { ... }`
// data-plane block must be declared, and an unenrolled workload registers
// over the dashboard listener, so `dashboard_listen` must not be unset or
// loopback-only. Mirrors how the OIDC enrollment plugin validates
// gateway-level preconditions after per-block decode.
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
	if reason := enrollmentListenerProblem(gw.Settings.DashboardListen); reason != "" {
		return hcl.Diagnostics{&hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "enrollment requires a routable dashboard_listen",
			Detail:   fmt.Sprintf("Workloads register over the dashboard listener before they have a tunnel, but %s. Set `dashboard_listen` to an address they can reach, for example \"0.0.0.0:8080\".", reason),
		}}
	}
	return validateTunnelSplitCIDRs(gw)
}

// enrollmentListenerProblem returns why listen cannot accept registrations
// from workloads, or "" when it can. A hostname other than localhost is
// accepted; it resolves at startup.
func enrollmentListenerProblem(listen string) string {
	if strings.TrimSpace(listen) == "" {
		return "`dashboard_listen` is not set"
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Sprintf("`dashboard_listen` %q is not a host:port address", listen)
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Sprintf("`dashboard_listen` %q is loopback-only", listen)
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return fmt.Sprintf("`dashboard_listen` %q is loopback-only", listen)
	}
	return ""
}
