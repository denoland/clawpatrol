package main

import (
	"context"
	"io"
	"net"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// passthrough is a no-op tunnel: Dial does net.Dial and pumps bytes
// in both directions. Exists to demonstrate the tunnel API surface;
// real tunnel plugins would establish the underlying transport
// (Wireguard, Tailscale, SSH, ...) inside Open and reuse it across
// many Dials.
func passthroughDef() pluginsdk.TunnelDef {
	return pluginsdk.TunnelDef{
		TypeName: "passthrough",
		Schema:   pluginsdk.Schema{},
		Open: func(ctx context.Context, req pluginsdk.TunnelOpenRequest) (any, error) {
			// No state to keep; the tunnel name itself is enough.
			return req.TunnelInstance, nil
		},
		Dial: func(ctx context.Context, req pluginsdk.TunnelDialRequest, upstream net.Conn) error {
			c, err := net.Dial(req.Network, req.Addr)
			if err != nil {
				return err
			}
			defer c.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
			go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
			<-done
			return nil
		},
		Close: func(_ context.Context, _ any) error { return nil },
	}
}
