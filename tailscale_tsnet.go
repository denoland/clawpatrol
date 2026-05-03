//go:build tsnet

// Optional embedded-Tailscale-node listener. Pulls a huge dep tree
// (~500 packages, ~10x slower compile), so opt-in via `-tags tsnet`.

package main

import (
	"net"
	"os"

	"github.com/denoland/clawpatrol-go/config"
	"tailscale.com/tsnet"
)

func openListener(cfg *config.Gateway) (net.Listener, error) {
	authKey := cfg.Tailscale.AuthKey
	if authKey == "" {
		authKey = os.Getenv("TS_AUTHKEY")
	}
	if authKey == "" {
		return net.Listen("tcp", cfg.Listen)
	}
	hn := cfg.Tailscale.Hostname
	if hn == "" {
		hn = "clawpatrol-gateway"
	}
	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: cfg.Tailscale.ControlURL,
		Dir:        cfg.Tailscale.StateDir,
	}
	port := cfg.Listen
	if port == "" {
		port = ":443"
	}
	return s.Listen("tcp", port)
}
