//go:build !tsnet

// Default build: plain TCP listener. tsnet (embedded Tailscale node)
// pulls ~500 packages and slows compile by 10x — overkill for the 99%
// case where tailscaled runs separately on the host. Build with
// `-tags tsnet` to opt into the embedded node.

package main

import (
	"fmt"
	"net"
)

func openListener(cfg *Config) (net.Listener, error) {
	if cfg.Gateway.AuthKey != "" {
		return nil, fmt.Errorf(
			"tailscale.authkey set but binary built without tsnet — " +
				"either install tailscaled separately and drop authkey, " +
				"or rebuild with: go build -tags tsnet ./...")
	}
	return net.Listen("tcp", cfg.Listen)
}
