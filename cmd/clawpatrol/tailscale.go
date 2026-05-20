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
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"

	"github.com/denoland/clawpatrol/internal/config"
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
// needed). Returns the *tsnet.Server. All MITM traffic from tsnet
// clients is intercepted via RegisterFallbackTCPHandler (set up by
// runGateway), so we don't open a tailnet :443 listener here.
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
	// Bring tsnet up. We don't need a tailnet TCP listener — exit-node
	// routing delivers client conns straight to RegisterFallbackTCPHandler.
	// Listen on a throwaway port to drive s.Up() since tsnet has no other
	// public bring-up API and never exposes this listener to callers.
	bringUp, err := s.Listen("tcp", ":0")
	if err != nil {
		return nil, nil, err
	}
	_ = bringUp.Close()
	// Advertise exit routes so whole-machine and per-process tsnet
	// clients can use this node as a Tailscale exit node.
	go advertiseExitRoutes(s)
	return s, nil, nil
}

// startFunnelListener opens a Tailscale Funnel listener on :443 (internet
// → tsnet, FunnelOnly so tailnet connections still go to the normal
// MITM listener). Strict path allowlist — only the routes a client
// genuinely cannot reach via tailnet are exposed:
//
//   - /api/onboard/start, /poll, /claim: bootstrap before the client
//     has any tailnet identity. /claim is used by WG mode after
//     wg-quick takes the default route through the tunnel (the public
//     URL goes unreachable, so the client has to claim before then,
//     which means right after /poll returns — still no tailnet
//     identity at that point).
//   - /api/cred/*: signed/HMAC'd credential webhooks (OAuth callbacks
//     from Notion/GitHub/etc.) which arrive from external providers.
//   - /api/hitl/operations/*/status: operation-scoped capability URLs
//     returned in async HITL 202 responses so off-tailnet agents can poll
//     without exposing their peer API bearer token.
//
// Everything else (dashboard, /api/onboard/approve, lookup, peer APIs,
// env-pushdown, /ca.crt) is reachable only over the tailnet.
func startFunnelListener(s *tsnet.Server, mux http.Handler) {
	ln, err := s.ListenFunnel("tcp", ":443", tsnet.FunnelOnly())
	if err != nil {
		log.Printf("tsnet: funnel :443: %v (join/webhook endpoints not internet-reachable; enable Funnel for this node in the Tailscale admin console)", err)
		return
	}
	log.Printf("tsnet: Funnel listening on :443 — allowlist: /api/onboard/{start,poll,claim}, /api/cred/*, /api/hitl/operations/*/status")
	go func() { _ = http.Serve(ln, funnelPublicHandler(mux)) }()
}

type funnelPublicRequestContextKey struct{}

func funnelPublicHandler(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if funnelAllowsPublicPath(r.URL.Path) {
			ctx := context.WithValue(r.Context(), funnelPublicRequestContextKey{}, true)
			mux.ServeHTTP(rw, r.WithContext(ctx))
			return
		}
		http.NotFound(rw, r)
	})
}

func isFunnelPublicRequest(ctx context.Context) bool {
	fromFunnel, _ := ctx.Value(funnelPublicRequestContextKey{}).(bool)
	return fromFunnel
}

func funnelAllowsPublicPath(path string) bool {
	switch path {
	case "/api/onboard/start", "/api/onboard/poll", "/api/onboard/claim":
		return true
	}
	if strings.HasPrefix(path, "/api/cred/") {
		return true
	}
	_, ok := hitlOperationIDFromStatusPath(path)
	return ok
}

// tsnetCertDomain returns the first HTTPS cert domain for the embedded
// tsnet node (e.g. "clawpatrol-gateway.ts.net"), or "" if not available.
// Used to auto-populate public_url when funnel = true and public_url is
// not set in gateway.hcl.
func tsnetCertDomain(s *tsnet.Server) string {
	lc, err := s.LocalClient()
	if err != nil {
		return ""
	}
	st, err := lc.StatusWithoutPeers(context.Background())
	if err != nil || len(st.CertDomains) == 0 {
		return ""
	}
	return "https://" + st.CertDomains[0]
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
