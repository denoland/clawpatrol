// Gateway control-plane listener. When the operator's HCL sets the
// top-level `authkey = "..."` (or TS_AUTHKEY is in the env), the
// gateway joins a tailnet via an embedded tsnet.Server and accepts
// agent traffic on its tailnet IP. Otherwise a plain TCP listener
// on cfg.Listen is used.
//
// tsnet's dep tree is unconditionally compiled in — the tunnel
// package's tailscale plugin already pulls it, so there's no
// compile-time saving in keeping a build-tag split here.

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"tailscale.com/tsnet"

	"github.com/denoland/clawpatrol/config"
)

// gatewayTsnetDir is the per-gateway tsnet state directory, carved out
// of the resolved state_dir. Setting tsnet.Server.Dir explicitly keeps
// tsnet from consulting $XDG_CONFIG_HOME / $HOME — those may be unset
// under systemd-hardened units, container runtimes, and similar
// minimal environments. Mode 0700 because tsnet stores private node
// keys here.
func gatewayTsnetDir(stateDir string) (string, error) {
	if stateDir == "" {
		return "", fmt.Errorf("tsnet: state_dir is empty (resolved gateway state_dir required)")
	}
	dir := filepath.Join(stateDir, "tsnet")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("tsnet state dir: %w", err)
	}
	return dir, nil
}

func openListener(cfg *config.Gateway, stateDir string) (net.Listener, error) {
	authKey := cfg.AuthKey
	if authKey == "" {
		authKey = os.Getenv("TS_AUTHKEY")
	}
	if authKey == "" {
		return net.Listen("tcp", cfg.Listen)
	}
	hn := cfg.Hostname
	if hn == "" {
		hn = "clawpatrol-gateway"
	}
	dir, err := gatewayTsnetDir(stateDir)
	if err != nil {
		return nil, err
	}
	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: cfg.ControlURL,
		Dir:        dir,
	}
	port := cfg.Listen
	if port == "" {
		port = ":443"
	}
	return s.Listen("tcp", port)
}
