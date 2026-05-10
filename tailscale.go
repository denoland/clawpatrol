// Gateway control-plane listener. When the operator's HCL sets
// `gateway { authkey = "..." }` (or TS_AUTHKEY is in the env), the
// gateway joins a tailnet via an embedded tsnet.Server and accepts
// agent traffic on its tailnet IP. Otherwise a plain TCP listener
// on cfg.Listen is used.
//
// tsnet's dep tree is unconditionally compiled in — the tunnel
// package's tailscale plugin already pulls it, so there's no
// compile-time saving in keeping a build-tag split here.

package main

import (
	"net"
	"os"

	"tailscale.com/tsnet"

	"github.com/denoland/clawpatrol/config"
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
