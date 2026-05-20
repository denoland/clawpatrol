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
	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
)

// passthroughBuild is the Build hook for endpoint plugins that don't
// derive any record beyond their decoded body.
func passthroughBuild(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return d, nil
}
