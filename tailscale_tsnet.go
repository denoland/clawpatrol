//go:build tsnet

// Optional embedded-Tailscale-node listener. Pulls a huge dep tree
// (~500 packages, ~10x slower compile), so opt-in via `-tags tsnet`.

package main

import (
	"net"
	"os"

	"tailscale.com/tsnet"
)

func openListener(cfg *Config) (net.Listener, error) {
	authKey := cfg.Gateway.AuthKey
	if authKey == "" {
		authKey = os.Getenv("TS_AUTHKEY")
	}
	if authKey == "" {
		return net.Listen("tcp", cfg.Listen)
	}
	hn := cfg.Gateway.Hostname
	if hn == "" {
		hn = "clawpatrol-gateway"
	}
	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: cfg.Gateway.ControlURL,
		Dir:        cfg.Gateway.StateDir,
	}
	port := cfg.Listen
	if port == "" {
		port = ":443"
	}
	return s.Listen("tcp", port)
}
