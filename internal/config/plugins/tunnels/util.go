// Package tunnels hosts the built-in tunnel plugins. Each provider
// lives in its own file (local_command.go, ssh_port_forward.go, …)
// and registers itself via init(). Shared helpers + the registration
// boilerplate live here.
package tunnels

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
)

// newer returns a New() func that allocates a fresh *T.
func newer[T any]() func() any { return func() any { return new(T) } }

// passthrough is the Build hook tunnel plugins reuse when their HCL
// body needs no Build-time massaging — same shape as endpoints' /
// credentials' passthroughBuild, just spelled here so each plugin
// package owns its own helpers.
func passthrough(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return decoded, nil
}

// commonRefs are the framework-level bare-name references every
// tunnel block accepts: `via = <other-tunnel>` and `credential =
// <credential>`. Plugins concatenate this with their own type-
// specific refs when they register.
var commonRefs = []config.RefSpec{
	{Path: "Via", Kind: config.KindTunnel, Optional: true},
	{Path: "Credential", Kind: config.KindCredential, Optional: true},
}

// emitCommon writes the framework-level attrs (share, keepalive,
// via, credential) onto an hclwrite block body. Plugins call it
// from their own Emit hook before laying down their plugin-specific
// fields. via / credential are emitted as bare identifiers so
// reload round-trips them as references, not strings.
func emitCommon(b *hclwrite.Body, c config.TunnelCommon) {
	if c.Share != "" {
		b.SetAttributeValue("share", cty.StringVal(c.Share))
	}
	if c.Keepalive != "" {
		b.SetAttributeValue("keepalive", cty.StringVal(c.Keepalive))
	}
	if c.Via != "" {
		config.SetIdent(b, "via", c.Via)
	}
	if c.Credential != "" {
		config.SetIdent(b, "credential", c.Credential)
	}
}

// readinessTCP polls dst with TCP-Connect at interval until either
// the dial succeeds (returns nil) or ctx fires (returns ctx.Err()).
// Used by tunnel plugins that bring up a local listener and need to
// know when it's accepting before returning from Open.
func readinessTCP(ctx context.Context, dst string, interval time.Duration) error {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		c, err := (&net.Dialer{Timeout: interval}).DialContext(ctx, "tcp", dst)
		if err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("readiness probe %s never accepted: %w", dst, ctx.Err())
		case <-t.C:
		}
	}
}
