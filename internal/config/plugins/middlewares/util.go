// Package middlewares hosts the built-in HTTP request-side middleware
// plugins. Each type lives in its own file (anthropic_system_prompt.go,
// …) and registers itself via init(). A middleware is an
// endpoint-attached hook that sees each request after credential
// injection and may rewrite its body before the upstream forward; the
// runtime contract is runtime.HTTPMiddleware.
package middlewares

import (
	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
)

// newer returns a New() func that allocates a fresh *T.
func newer[T any]() func() any { return func() any { return new(T) } }

// passthrough is the Build hook middleware plugins reuse when their HCL
// body needs no Build-time massaging — mirrors the same helper in the
// credentials / endpoints / tunnels plugin packages.
func passthrough(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return decoded, nil
}
