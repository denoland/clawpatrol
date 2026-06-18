package main

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// passthrough is a no-op tunnel: Dial opens the upstream and pumps bytes
// in both directions. Exists to demonstrate the tunnel API surface; real
// tunnel plugins would establish the underlying transport (Wireguard,
// Tailscale, SSH, ...) inside Open and reuse it across many Dials.
//
// It dials through the gateway's brokered DialUpstream rather than a raw
// net.Dial, so it needs no network of its own (network = "none"). For a
// top-level tunnel the gateway dials directly, so this is a true no-op;
// see the socks tunnel for one that does real work with the same dial.
func passthroughDef() pluginsdk.TunnelDef {
	return pluginsdk.TunnelDef{
		TypeName: "example_passthrough",
		Schema:   pluginsdk.Schema{},
		Open: func(_ context.Context, req pluginsdk.TunnelOpenRequest) (any, error) {
			// No state to keep; the tunnel name itself is enough.
			return req.TunnelInstance, nil
		},
		Dial: func(ctx context.Context, req pluginsdk.TunnelDialRequest, upstream net.Conn) error {
			if req.DialUpstream == nil {
				return errors.New("example_passthrough: gateway has no transport dial support")
			}
			c, err := req.DialUpstream(ctx, req.Network, req.Addr)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
			go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
			<-done
			return nil
		},
		Close: func(_ context.Context, _ any) error { return nil },
	}
}
