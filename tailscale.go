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
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

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
		if isTailscaleControlMode(cfg.Control) {
			// System Tailscale is already running on this host; listen on
			// whatever cfg.Listen says (typically the tailnet IP:port set by
			// the operator). Ephemeral tsnet clients reach us over the mesh.
			addr := cfg.Listen
			if addr == "" {
				addr = ":8443"
			}
			ln4, err := net.Listen("tcp", addr)
			if err != nil {
				return nil, err
			}
			// Also listen on the tailscale0 IPv6 address so that
			// ip6tables REDIRECT (exit-node path) can reach the gateway.
			// The REDIRECT rewrites the destination to the primary IPv6 of
			// the incoming interface; without this second listener those
			// connections are refused.
			_, port, _ := net.SplitHostPort(addr)
			if port == "" {
				port = "8443"
			}
			if ip6 := tailscaleIfaceIPv6(); ip6 != "" {
				ln6, err := net.Listen("tcp6", net.JoinHostPort(ip6, port))
				if err != nil {
					log.Printf("warning: IPv6 tailnet listener on [%s]:%s failed: %v (exit-node IPv6 flows won't be intercepted)", ip6, port, err)
				} else {
					return newMultiListener(ln4, ln6), nil
				}
			}
			return ln4, nil
		}
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
	port := cfg.Listen
	if port == "" {
		port = ":443"
	}
	return s.Listen("tcp", port)
}

// tailscaleIfaceIPv6 returns the first global unicast IPv6 address on
// the tailscale0 interface (fd7a::/10 range). Returns "" if not found.
func tailscaleIfaceIPv6() string {
	iface, err := net.InterfaceByName("tailscale0")
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.To4() != nil || !ip.IsGlobalUnicast() {
			continue
		}
		// Tailscale IPv6 addresses start with fd7a:
		if strings.HasPrefix(ip.String(), "fd7a:") {
			return ip.String()
		}
	}
	return ""
}

// multiListener merges two net.Listeners into one Accept stream.
// Used to bind both the IPv4 tailnet address and the IPv6 tailnet
// address so that ip6tables REDIRECT (exit-node path) can reach the
// gateway alongside normal IPv4 connections.
type multiListener struct {
	ch   chan net.Conn
	addr net.Addr
	done chan struct{}
}

func newMultiListener(listeners ...net.Listener) net.Listener {
	ml := &multiListener{
		ch:   make(chan net.Conn, 64),
		addr: listeners[0].Addr(),
		done: make(chan struct{}),
	}
	for _, ln := range listeners {
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					select {
					case <-ml.done:
					default:
						log.Printf("multiListener accept: %v", err)
					}
					return
				}
				ml.ch <- c
			}
		}(ln)
	}
	return ml
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-m.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	return nil
}

func (m *multiListener) Addr() net.Addr { return m.addr }
