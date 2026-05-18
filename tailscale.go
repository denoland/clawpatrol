// Gateway control-plane listener. When the operator's HCL sets the
// top-level `authkey = "..."` (or TS_AUTHKEY is in the env), the
// gateway joins a tailnet via an embedded tsnet.Server and accepts
// agent traffic on its tailnet IP — this is the meaningful Listener
// for tsnet-mode deployments. The embedded tsnet.Server also acts as
// a Tailscale exit node: RegisterFallbackTCPHandler intercepts all
// TCP forwarded through the node so whole-machine clients get the
// same MITM treatment as per-process clawpatrol-run clients. No
// system tailscaled, iptables, or sudo required.
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

// openListener returns the gateway's primary TCP listener.
//
// Tailscale control mode: always uses an embedded tsnet.Server.
// Requires authkey in HCL or TS_AUTHKEY env (no system tailscaled
// needed). Returns the *tsnet.Server so the caller can register a
// fallback TCP handler for whole-machine exit-node traffic.
//
// WireGuard mode: returns nil server and a loopback TCP listener.
func openListener(cfg *config.Gateway, stateDir string) (*tsnet.Server, net.Listener, error) {
	if !isTailscaleControlMode(cfg.Control) {
		// WireGuard mode: bind loopback regardless of cfg.Listen's
		// host portion. See the file-level comment.
		host, port, err := net.SplitHostPort(cfg.Listen)
		if err != nil || port == "" {
			port = "8443"
		}
		if host != "" && host != "127.0.0.1" && host != "::1" {
			log.Printf("WARNING: listen %q overridden to loopback in WireGuard mode; agent traffic flows through the WG tunnel, this socket is for local debugging only.", cfg.Listen)
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
		return nil, ln, err
	}

	authKey := cfg.AuthKey
	if authKey == "" {
		authKey = os.Getenv("TS_AUTHKEY")
	}
	if authKey == "" {
		return nil, nil, fmt.Errorf("tailscale mode requires authkey = \"...\" in gateway.hcl or TS_AUTHKEY env var (embedded tsnet — no system tailscaled needed)")
	}

	hn := cfg.Hostname
	if hn == "" {
		hn = "clawpatrol-gateway"
	}
	dir, err := gatewayTsnetDir(stateDir)
	if err != nil {
		return nil, nil, err
	}
	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: cfg.ControlURL,
		Dir:        dir,
	}
	_, portStr, _ := net.SplitHostPort(cfg.Listen)
	if portStr == "" {
		portStr = "443"
	}
	ln, err := s.Listen("tcp", ":"+portStr)
	if err != nil {
		return nil, nil, err
	}
	// Advertise exit routes so whole-machine clients can use this node
	// as a Tailscale exit node. s.Up() completed inside s.Listen(), so
	// LocalClient is available. Async to avoid blocking runGateway.
	go advertiseExitRoutes(s)
	return s, ln, nil
}

// advertiseExitRoutes calls EditPrefs to make this tsnet node an exit
// node (advertises 0.0.0.0/0 and ::/0). Whole-machine clients on the
// same tailnet can then route all traffic through this gateway; exit
// flows are intercepted via RegisterFallbackTCPHandler in runGateway.
func advertiseExitRoutes(s *tsnet.Server) {
	lc, err := s.LocalClient()
	if err != nil {
		log.Printf("tsnet: LocalClient for exit routes: %v", err)
		return
	}
	routes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	if _, err := lc.EditPrefs(context.Background(), &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs:              ipn.Prefs{AdvertiseRoutes: routes},
	}); err != nil {
		log.Printf("tsnet: advertise exit routes: %v", err)
	} else {
		log.Printf("tsnet: advertised exit routes (0.0.0.0/0, ::/0)")
	}
}
