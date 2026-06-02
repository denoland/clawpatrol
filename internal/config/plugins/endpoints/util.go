// Package endpoints registers every built-in endpoint plugin.
//
// An endpoint is a typed network target: hosts (or RDS host /
// kubernetes server) plus protocol-family connection parameters. The
// credential-binding lives on the credential block now — each
// credential declares which endpoint(s) it authenticates against via
// the framework-level `endpoint = X` (singular) or
// `endpoints = [X, Y, ...]` (multi) attrs, with an optional
// `placeholder` for dispatch among multiple credentials at one
// endpoint.
//
// Per-endpoint plugins live in their own file (https.go, postgres.go,
// kubernetes.go, clickhouse_https.go, clickhouse_native.go); this
// file is the cross-cutting helpers they share.
package endpoints

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/hostmatch"
)

// passthroughBuild is the Build hook for endpoint plugins that don't
// derive any record beyond their decoded body.
func passthroughBuild(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return d, nil
}

// validateHosts checks the host strings the plugin body exposes via
// EndpointHosts(). It rejects malformed entries (bad ports,
// malformed wildcards) and within-endpoint duplicates. Endpoint
// plugins whose hosts come from a single field (postgres' Host,
// kubernetes' Server) also pass through here — EndpointHosts
// returns a one-element slice for them, so the same validation
// applies.
func validateHosts(d any, name string, defRange hcl.Range) hcl.Diagnostics {
	hosts := extractHostsAny(d)
	if len(hosts) == 0 {
		return nil
	}
	var diags hcl.Diagnostics
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if err := hostmatch.ValidateHost(h); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Malformed host on endpoint %q", name),
				Detail:   fmt.Sprintf("hosts entry %q: %v", h, err),
				Subject:  &defRange,
			})
			continue
		}
		key := strings.ToLower(h)
		if _, dup := seen[key]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Duplicate host on endpoint %q", name),
				Detail:   fmt.Sprintf("hosts entry %q appears more than once", h),
				Subject:  &defRange,
			})
			continue
		}
		seen[key] = struct{}{}
	}
	return diags
}

// extractHostsAny mirrors compile.extractHosts but lives in this
// package so the Validate hooks can call it without dragging the
// internal compile pass in.
func extractHostsAny(body any) []string {
	if h, ok := body.(interface{ EndpointHosts() []string }); ok {
		return h.EndpointHosts()
	}
	return nil
}

// hostsValidate is the Validate hook every endpoint plugin uses to
// catch malformed / duplicate `hosts = [...]` entries at config-load
// time. Registered as Plugin.Validate on every endpoint type;
// per-plugin Validate hooks that need to layer additional checks on
// top should chain to validateHosts explicitly.
func hostsValidate(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	return validateHosts(d, name, ctx.Block.DefRange)
}
