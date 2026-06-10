// Gateway transport listeners.
//
// `tailscale { }` block present: the gateway joins a tailnet via an
// embedded tsnet.Server and accepts agent traffic on its tailnet IP.
// The embedded tsnet.Server also acts as a Tailscale exit node:
// RegisterFallbackTCPHandler intercepts all TCP forwarded through the
// node so whole-machine clients get the same MITM treatment as
// per-process clawpatrol-run clients. No system tailscaled, iptables,
// or sudo required.
//
// `wireguard { }` block present: the gateway runs an embedded
// userspace WireGuard server (see wireguard.go). Agent TLS flows
// through the WG netstack's promiscuous forwarder; main.go's
// tcpDispatch routes dst port 443 to g.handle. Alongside the
// netstack we also open a loopback TCP listener on 127.0.0.1:8443
// (configurable via wireguard.host_loopback_port) for host-local
// clients — single-host deployments (the gateway
// running under one user account, clawpatrol-run invoked from
// another on the same machine, loopback WG between them) are a
// first-class pattern, not a debug mode.
//
// Both blocks present: the gateway runs both transports concurrently.
// Peers from either transport land in the same g.handle path.
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
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/netstack"

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

// defaultHostLoopbackPort is the TCP port the gateway binds on
// 127.0.0.1 for host-local clients when wireguard.host_loopback_port
// is unset.
const defaultHostLoopbackPort = 8443

// hostLoopbackPort resolves the loopback TCP port the gateway binds
// for host-local clients, honoring wireguard.host_loopback_port and
// falling back to defaultHostLoopbackPort when unset (0).
func hostLoopbackPort(port int) int {
	if port != 0 {
		return port
	}
	return defaultHostLoopbackPort
}

// openListener brings up the gateway's transport listeners. Either
// or both of the returned values may be non-nil depending on which
// transport blocks the operator declared:
//
//   - WireGuard enabled → returns a loopback TCP listener on
//     127.0.0.1:<host_loopback_port> (default 8443). Host-local
//     agents (e.g. clawpatrol-run from a
//     different UID on the same box) connect directly. Off-host
//     agents reach g.handle via the WG netstack's promiscuous
//     forwarder; that path doesn't touch this socket.
//   - Tailscale enabled → returns the *tsnet.Server. All MITM
//     traffic from tsnet clients is intercepted via
//     RegisterFallbackTCPHandler (set up by runGateway), so we
//     don't open a tailnet :443 listener here.
//
// Configs without either block fail validation at Load time, so this
// function never returns (nil, nil, nil).
func openListener(cfg *config.Gateway, stateDir string) (*tsnet.Server, net.Listener, error) {
	var ln net.Listener
	if cfg.IsWireGuardEnabled() {
		var err error
		addr := fmt.Sprintf("127.0.0.1:%d", hostLoopbackPort(cfg.Settings.WireGuard.HostLoopbackPort))
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return nil, nil, err
		}
	}

	if !cfg.IsTailscaleEnabled() {
		return nil, ln, nil
	}

	ts := cfg.Settings.Tailscale
	authKey := ts.AuthKey
	if authKey == "" {
		authKey = os.Getenv("TS_AUTHKEY")
	}
	if authKey == "" {
		if ln != nil {
			_ = ln.Close()
		}
		return nil, nil, fmt.Errorf("tailscale block requires authkey = \"...\" in gateway.hcl or TS_AUTHKEY env var (embedded tsnet — no system tailscaled needed)")
	}

	hn := ts.Hostname
	if hn == "" {
		hn = "clawpatrol-gateway"
	}
	dir, err := gatewayTsnetDir(stateDir)
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return nil, nil, err
	}
	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: ts.ControlURL,
		Dir:        dir,
	}
	// Bring tsnet up. We don't need a tailnet TCP listener — exit-node
	// routing delivers client conns straight to RegisterFallbackTCPHandler.
	// Listen on a throwaway port to drive s.Up() since tsnet has no other
	// public bring-up API and never exposes this listener to callers.
	bringUp, err := s.Listen("tcp", ":0")
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return nil, nil, err
	}
	_ = bringUp.Close()
	// Route advertisement (exit routes + VIP subnet routes) happens in
	// runGateway via advertiseExitRoutes once the dnsvip allocator's
	// CIDRs are known.
	return s, ln, nil
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
//
// The dnsvip CIDRs are advertised alongside as plain subnet routes.
// The exit-node /0 advertisements alone do NOT make the v4 VIPs
// reachable: tailscaled derives the inbound packet filter's accept
// set (localNets) locally from AdvertiseRoutes, and a /0 route is
// deliberately shrunk to "the internet" (guest-wifi semantics) by
// subtracting removeFromDefaultRoute — which contains 10.0.0.0/8 and
// therefore the v4 VIP range. Inbound exit-node flows to a v4 VIP
// were dropped by the filter's "destination not allowed" check before
// any clawpatrol handler ran, for every client kind (tsnet
// `clawpatrol run` and whole-machine alike). The v6 list strips only
// link-local/multicast/fd7a:115c:a1e0::/48, so fd78:: VIPs always
// passed — which is why v6-capable clients masked the bug. See
// ipn/ipnlocal updateFilterLocked + shrinkDefaultRoute.
//
// Advertising the VIP CIDRs as non-default routes puts them in
// localNets verbatim, so VIP-bound flows reach
// RegisterFallbackTCPHandler / the UDP catch-all like any other
// intercepted traffic. This is purely node-local: it does not require
// the routes to be approved in the tailnet (clients route VIPs via
// the exit-node /0, not via subnet routes). (#653)
func advertiseExitRoutes(s *tsnet.Server, vipCIDRs ...netip.Prefix) {
	lc, err := s.LocalClient()
	if err != nil {
		log.Printf("tsnet: LocalClient for exit routes: %v", err)
		return
	}
	routes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	for _, p := range vipCIDRs {
		if p.IsValid() {
			routes = append(routes, p)
		}
	}
	if _, err := lc.EditPrefs(context.Background(), &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs:              ipn.Prefs{AdvertiseRoutes: routes},
	}); err != nil {
		log.Printf("tsnet: advertise exit routes: %v", err)
	} else {
		log.Printf("tsnet: advertised exit routes (%s)", routes)
	}
}

// installTsnetUDPCatchAll layers a catch-all UDP interceptor onto
// tsnet's internal netstack so UDP forwarded through the gateway's
// exit-node advertisement reaches clawpatrol instead of tsnet's default
// forwarder — the same dispatch WG mode's promiscuous netstack already
// applies to all UDP:
//
//   - UDP/53 to ANY destination → dnsvip (so an exit-node client whose
//     system resolver targets 8.8.8.8 still resolves internal hostnames
//     like clickhouse-o11y / *.denosr-staging.internal and allocates the
//     VIPs endpoint dispatch relies on);
//   - other UDP from an onboarded peer → relayUDP (so a tsnet-mode
//     `clawpatrol run` child gets arbitrary UDP, e.g. QUIC or a custom
//     protocol, carried by clawpatrol rather than silently leaving via
//     tsnet's default forwarder).
//
// A tsnet client's Dial("udp") to a public IP does traverse this hook
// (verified on a two-node exit-node setup), so no UDP-over-TCP framing
// is needed to carry arbitrary UDP — the gateway already receives it.
//
// Non-onboarded sources fall through to tsnet's default handler: the
// gateway intercepts UDP for the agents it serves without becoming an
// open UDP proxy for any tailnet node that happens to pin it as an exit
// node.
//
// tsnet exposes RegisterFallbackTCPHandler for catch-all TCP but has no
// UDP equivalent (ListenPacket requires a concrete bind IP). The hook is
// GetUDPHandlerForFlow on the underlying *netstack.Impl, reached via
// tsnet.Server.Sys().Netstack. The Sys() doc warns "not a stable API" —
// pinned via go.mod; type-assert + nil checks log-and-no-op rather than
// crash if a Tailscale upgrade renames the field.
//
// Must be called after the tsnet.Server has been started (Start()
// triggered by an earlier Listen/ListenPacket); only then is the
// netstack subsystem registered.
func (g *Gateway) installTsnetUDPCatchAll(s *tsnet.Server) {
	if s == nil {
		return
	}
	sys := s.Sys()
	if sys == nil {
		log.Printf("tsnet: UDP catch-all skipped — Sys() returned nil")
		return
	}
	impl, ok := sys.Netstack.GetOK()
	if !ok {
		log.Printf("tsnet: UDP catch-all skipped — netstack subsystem not registered yet")
		return
	}
	ns, ok := impl.(*netstack.Impl)
	if !ok {
		log.Printf("tsnet: UDP catch-all skipped — Sys().Netstack is %T not *netstack.Impl", impl)
		return
	}
	orig := ns.GetUDPHandlerForFlow
	ns.GetUDPHandlerForFlow = func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		switch g.tsnetUDPDisposition(dst, src.Addr()) {
		case udpDNS:
			return g.serveTsnetUDPDNSFlow, true
		case udpDrop:
			return func(c nettype.ConnPacketConn) { _ = c.Close() }, true
		case udpRelay:
			return func(c nettype.ConnPacketConn) {
				relayUDP(c, dst.Addr().String(), dst.Port())
			}, true
		default: // udpPassthrough
			if orig != nil {
				return orig(src, dst)
			}
			return nil, false
		}
	}
	log.Printf("tsnet: UDP catch-all installed (:53 → dnsvip, :443 QUIC dropped for VIPs, other → relay for onboarded peers)")
}

// udpDisposition is what the gateway does with a forwarded UDP flow.
type udpDisposition int

const (
	udpPassthrough udpDisposition = iota // leave it to tsnet's default handler
	udpDNS                               // intercept via dnsvip
	udpDrop                              // black-hole (force a TCP fallback)
	udpRelay                             // transparently relay to the upstream
)

// tsnetUDPDisposition decides how an exit-node UDP flow is handled.
//
//   - UDP/53 → dnsvip (resolve via clawpatrol regardless of resolver IP).
//   - UDP/443 to an intercepted (VIP'd) host → drop. That's QUIC / HTTP-3
//     to a host we MITM; relaying it would let HTTPS ride UDP straight
//     past the TCP/443 SNI-peek MITM. Dropping makes the client fall back
//     to TCP/443, which the gateway intercepts. UDP/443 to a host we
//     pass through (no VIP) is *not* dropped — we don't intercept that
//     host's HTTPS either, so there's nothing to bypass, and breaking its
//     HTTP/3 would be gratuitous. (WG mode's udpDispatch does the same.)
//     Limitation: an https-mitm endpoint bound to an IP literal isn't
//     VIP'd, so its UDP/443 isn't dropped here — rare (those are dialled
//     by IP, e.g. kubectl, and over TCP), and Alt-Svc stripping still
//     suppresses h3 discovery for it on the MITM'd TCP path.
//   - other UDP from an onboarded peer → relay (e.g. NTP, a custom
//     protocol, or QUIC to a passed-through host).
//   - everything else → tsnet's default handler.
func (g *Gateway) tsnetUDPDisposition(dst netip.AddrPort, src netip.Addr) udpDisposition {
	switch dst.Port() {
	case 53:
		if g.dnsvip != nil {
			return udpDNS
		}
	case 443:
		if g.dnsvip != nil && g.dnsvip.IsVIP(dst.Addr().String()) {
			return udpDrop
		}
	}
	if g.tsnetUDPPeerOnboarded(src) {
		return udpRelay
	}
	return udpPassthrough
}

// tsnetUDPPeerOnboarded reports whether an exit-node UDP flow's source
// is a peer clawpatrol has onboarded — the gate that keeps the UDP
// relay from acting as an open proxy for arbitrary tailnet nodes. The
// source arrives as the peer's tsnet address (its 100.x or fd7a ULA);
// daemonRegisterTsnetPeer maps both for a joined daemon, so a direct
// device lookup covers the steady state, with AgentIPFor resolving an
// alias to the canonical agent IP.
//
// Peer-authorization model adapted from #640 (@dhruvkelawala); the
// per-peer token promotion there has no analogue on the raw-UDP path,
// so a daemon's very first UDP before its register lands falls through
// to tsnet's default handler (the register completes on startup).
func (g *Gateway) tsnetUDPPeerOnboarded(addr netip.Addr) bool {
	if g.onboard == nil || !addr.IsValid() {
		return false
	}
	ip := canonicalPeerIP(addr.String())
	if g.onboard.HasDevice(ip) {
		return true
	}
	if canonical := g.onboard.AgentIPFor(ip); canonical != ip && g.onboard.HasDevice(canonical) {
		return true
	}
	return false
}

// serveTsnetUDPDNSFlow handles one UDP/53 flow from an exit-node
// client. tsnet calls this per-flow with a connected packet conn
// already bound to the (src, dst) tuple — Read/Write talk to the
// single peer, no addr juggling required. dnsvip.HandlePacket
// generates the response (VIP allocation for endpoint hostnames,
// upstream lookup otherwise). The loop covers the few resolvers
// that reuse the socket for follow-up queries; idle flows time
// out and close so we don't leak goroutines.
func (g *Gateway) serveTsnetUDPDNSFlow(c nettype.ConnPacketConn) {
	defer func() { _ = c.Close() }()
	if g.dnsvip == nil {
		return
	}
	buf := make([]byte, 65535)
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		resp := g.dnsvip.HandlePacket(buf[:n], "")
		if len(resp) == 0 {
			continue
		}
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}
