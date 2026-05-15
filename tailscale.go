// Gateway control-plane listener. When the operator's HCL sets the
// top-level `authkey = "..."` (or TS_AUTHKEY is in the env), the
// gateway joins a tailnet via an embedded tsnet.Server and accepts
// agent traffic on its tailnet IP — this is the meaningful Listener
// for tsnet-mode deployments.
//
// In WireGuard mode the listener is vestigial: agent TLS flows
// through the WG netstack's promiscuous forwarder inside the tunnel
// (main.go's tcpDispatch handles dst port 443), not through this
// socket. We still open a loopback listener so g.handle is reachable
// for in-process local debugging, but force the bind to 127.0.0.1
// regardless of cfg.Listen — historically operators set this to
// 0.0.0.0:8443, which combined with g.handle's "unknown SNI →
// splice" fall-through turned the socket into an open TLS proxy
// (security-review F-19).
//
// tsnet's dep tree is unconditionally compiled in — the tunnel
// package's tailscale plugin already pulls it, so there's no
// compile-time saving in keeping a build-tag split here.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"tailscale.com/ipn"
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
		// WireGuard mode: bind loopback regardless of cfg.Listen's
		// host portion. See the file-level comment.
		host, port, err := net.SplitHostPort(cfg.Listen)
		if err != nil || port == "" {
			port = "8443"
		}
		if host != "" && host != "127.0.0.1" && host != "::1" {
			log.Printf("WARNING: listen %q overridden to loopback in WireGuard mode; agent traffic flows through the WG tunnel, this socket is for local debugging only.", cfg.Listen)
		}
		return net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
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
	if err := advertiseGatewayExitNode(s); err != nil {
		log.Printf("tsnet: advertise exit node: %v (gateway will not appear in `tailscale exit-node list` until this is resolved; tailnet admin still has to approve the routes)", err)
	}
	port := cfg.Listen
	if port == "" {
		port = ":443"
	}
	return s.Listen("tcp", port)
}

// advertiseGatewayExitNode tells the embedded tsnet node to advertise
// itself as an exit node (`0.0.0.0/0` and `::/0` subnet routes), the
// in-process equivalent of `tailscale set --advertise-exit-node`. The
// tailnet admin still has to approve the advertised routes in the
// admin console before peers can select this node — advertising just
// registers the intent.
//
// Wiring this here keeps `clawpatrol run` (which targets the gateway
// via `ExitNodeIP`) symmetric with `clawpatrol gateway`: both sides
// of the tsnet path are configured by the gateway operator's HCL,
// no out-of-band `tailscale` CLI call needed.
func advertiseGatewayExitNode(s *tsnet.Server) error {
	if err := s.Start(); err != nil {
		return fmt.Errorf("tsnet start: %w", err)
	}
	lc, err := s.LocalClient()
	if err != nil {
		return fmt.Errorf("tsnet local client: %w", err)
	}
	_, err = lc.EditPrefs(context.Background(), &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}
	return nil
}
