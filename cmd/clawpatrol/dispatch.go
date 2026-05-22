package main

// Gateway connection-dispatch entry points. Every accepted client
// flow (WG promiscuous forwarder, tsnet exit-node fallback handler,
// host-local TCP listener) lands in one of these handlers, where the
// gateway decides what to do based on the destination address +
// port. HTTPS MITM lives in mitm.go; this file owns the routing,
// transparent splice/relay paths, and per-protocol entry points
// (postgres, VIP-bound binary endpoints, DNS-over-TCP). They share
// state through *Gateway — the only public surface here is the
// methods named below.

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/denoland/clawpatrol/cmd/clawpatrol/dnsvip"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func (g *Gateway) handle(raw net.Conn, dstIP string) {
	defer func() { _ = raw.Close() }()
	defer otelTrackConn("https_mitm")()
	host, prefix, err := peekSNI(raw)
	if err != nil {
		// No SNI — fall back to direct-IP endpoint lookup for kubernetes/https
		// endpoints whose `server` field is an IP literal (kubectl connects
		// by IP and never sends SNI).
		if dstIP != "" {
			c := wrapPeek(raw, prefix)
			pip := peerIP(c)
			profile := g.profileFor(pip)
			ep := runtime.HostEndpoint(g.Policy(), profile, dstIP)
			if ep != nil && isHTTPSMITMFamily(ep.Family) {
				log.Printf("sni-fallback: %s → %s", dstIP, ep.Name)
				g.mitmHTTPS(c, dstIP, ep)
				return
			}
		}
		log.Printf("sni: %v", err)
		return
	}
	c := wrapPeek(raw, prefix)
	log.Printf("sni-peek: %s", host)
	pip := peerIP(c)
	profile := g.profileFor(pip)
	ep := runtime.HostEndpoint(g.Policy(), profile, host)
	if ep == nil {
		// Host isn't bound to this profile's endpoint set. Apply the
		// `defaults.unknown_host` policy: passthrough today (matches
		// the v14 default). A "deny" mode would close the conn.
		g.splice(c, host)
		return
	}
	if isHTTPSMITMFamily(ep.Family) {
		// Every facet whose Transport() is "https-mitm" — https and
		// k8s today, future plugins tomorrow — terminates TLS here
		// and runs the request loop through mitmHTTPS. The facet's
		// PrepareRequest hook derives any per-family metadata
		// (URL → Meta for k8s) before the matcher walks.
		g.mitmHTTPS(c, host, ep)
		return
	}
	// Wire-protocol families (postgres / clickhouse_* / future
	// native plugins) dispatch through their own port handlers,
	// not through SNI peek on 443. Anything that lands here is
	// either an unknown family or a family without an HTTPS
	// transport — splice through.
	log.Printf("endpoint %s family %q: no https-mitm transport; passthrough", ep.Name, ep.Family)
	g.splice(c, host)
}

// isHTTPSMITMFamily reports whether the facet registered for family
// drives its wire through the HTTPS MITM handler. Replaces what used
// to be a hardcoded `case "http", "k8s"` so new HTTPS-shaped
// protocol facets (e.g. a future "openai" or "anthropic" family that
// wants per-family report fields beyond what http_rule offers) drop
// in without touching the dispatch switch.
func isHTTPSMITMFamily(family string) bool {
	if family == "" {
		return false
	}
	f := facet.Lookup(family)
	return f != nil && f.Transport() == "https-mitm"
}

// handlePostgresConn dispatches an inbound 5432 connection to the
// postgres endpoint runtime. The dstIP comes from the WG forwarder —
// agents resolve real RDS hostnames via public DNS and the gateway
// intercepts at L3, so dstIP is the upstream RDS / postgres server
// address. The endpoint is selected from the device's profile via
// dnsvip (tunneled endpoints) or ConnIndex (non-tunneled, dst-IP
// indexed). An unclaimed dst — no endpoint declares this host — is
// relayed verbatim so the connection fails on the real network
// rather than being silently routed to an unrelated postgres.
func (g *Gateway) handlePostgresConn(c net.Conn, dstIP string) {
	defer func() { _ = c.Close() }()
	defer otelTrackConn("pg_relay")()
	pip := peerIP(c)
	profile := g.profileFor(pip)
	agentPip := g.agentIPFor(c)

	policy := g.Policy()
	// Dispatch order:
	//
	//   1. dnsvip.LookupVIP — tunneled endpoints reach upstream via
	//      a synthetic hostname routed through a VIP, and conn-index
	//      intentionally skips them (would double-route past the
	//      tunnel).
	//   2. ConnIndex — non-tunneled endpoints indexed by DNS-resolved
	//      upstream IP. Filtered by profile so writer / readonly
	//      pointing at one RDS still picks the right one.
	//
	// No third "pick any postgres endpoint" fallback: an unclaimed
	// dst means no endpoint declares this host, and guessing routes
	// the connection to an unrelated database (e.g. an RDS hostname
	// silently terminating on a Cloud SQL tunnel).
	var ep *config.CompiledEndpoint
	if g.dnsvip != nil {
		if _, hits := g.dnsvip.LookupVIP(dstIP); len(hits) > 0 {
			cand := make([]*config.CompiledEndpoint, 0, len(hits))
			for _, h := range hits {
				if h.Endpoint != nil {
					cand = append(cand, h.Endpoint)
				}
			}
			ep = pickEndpointForProfile(cand, policy, profile)
		}
	}
	if ep == nil {
		if idx := g.connIdx.Load(); idx != nil {
			candidates := idx.Lookup(dstIP)
			ep = pickEndpointForProfile(candidates, policy, profile)
		}
	}
	if ep == nil {
		// No endpoint claims dstIP → relay verbatim. Closes when
		// either side hangs up.
		log.Printf("pg %s: no postgres endpoint in profile %q; relaying", dstIP, profile)
		g.wgRelay(c, dstIP, 5432)
		return
	}

	connRT, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime)
	if !ok {
		log.Printf("pg endpoint %q plugin lacks ConnEndpointRuntime", ep.Name)
		return
	}

	upstreamAddr := dstIP + ":5432"
	ch := &runtime.ConnHandle{
		Conn:     c,
		Endpoint: ep,
		Policy:   policy,
		Profile:  profile,
		PeerIP:   pip,
		Secrets:  g.secrets,
		Blobs:    g.blobs,
		DialUpstream: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Plugin asks for ep.Hosts[0]:port; we bypass DNS by
			// dialing the original upstream IP the WG forwarder
			// gave us. Plugin-supplied addr is ignored when it's
			// the endpoint's declared host (the common case).
			// dialThrough degrades to the direct dialer when ep
			// has no tunnel; this path is used by non-tunneled
			// postgres endpoints today (tunneled ones land in the
			// VIP dispatch path, not here).
			return g.dialThrough(ctx, ep, network, upstreamAddr)
		},
		Emit: func(ev runtime.ConnEvent) {
			if g.sink == nil {
				return
			}
			g.sink.Emit(Event{
				Mode: "pg", Family: ep.Family, Host: dstIP, AgentIP: agentPip,
				Method: ev.Verb, Path: ev.Summary,
				Action: ev.Action, Reason: ev.Reason,
				Facets:   ev.Facets,
				Endpoint: ep.Name, Rule: ev.Rule,
				Approver:     ev.Approver,
				ApproverType: ev.ApproverType,
				ApproverBy:   ev.ApproverBy,
			})
		},
		Approve: func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
			return g.runApproveChain(context.Background(), req.Stages, runApproveCtx{
				AgentIP: agentPip, Host: dstIP, Method: req.Verb, Path: req.Summary,
				Reason:   ifNotEmpty(req.Rule, func(r *config.CompiledRule) string { return r.Outcome.Reason }),
				Endpoint: ep, Rule: req.Rule, Profile: profile,
			})
		},
	}
	if err := connRT.HandleConn(context.Background(), ch); err != nil {
		log.Printf("pg %s: %v", dstIP, err)
	}
}

// handleVIPConn dispatches an inbound TCP connection whose dst IP
// falls in the dnsvip range. The VIP table maps the IP back to the
// hostname → endpoints that claimed a VIP at policy build; profile
// filter picks the one for this device. Today the only RequiresVIP
// plugin is "ssh", but the path is generic so future binary
// protocols (clickhouse_native with a hostname-keyed dispatch quirk,
// for instance) can plug in without a separate forwarder branch.
func (g *Gateway) handleVIPConn(c net.Conn, dstIP string, dstPort uint16) {
	defer otelTrackConn("vip_conn")()

	hostname, hits := g.dnsvip.LookupVIP(dstIP)
	if hostname == "" || len(hits) == 0 {
		log.Printf("vip %s:%d: VIP allocated but no endpoint binding (stale?); dropping", dstIP, dstPort)
		_ = c.Close()
		return
	}
	pip := peerIP(c)
	profile := g.profileFor(pip)
	policy := g.Policy()
	// Profile-filter the hits, then port-match. Port match handles
	// the case where one hostname is bound to multiple endpoints on
	// different ports (rare but legal).
	var ep *config.CompiledEndpoint
	var matchedPort uint16
	for _, h := range hits {
		if h.Endpoint == nil {
			continue
		}
		if profile != "" {
			if prof, ok := policy.Profiles[profile]; ok {
				if _, in := prof.Endpoints[h.Endpoint.Name]; !in {
					continue
				}
			}
		}
		if dstPort != 0 && h.Port != 0 && dstPort != h.Port {
			continue
		}
		ep = h.Endpoint
		matchedPort = h.Port
		break
	}
	if ep == nil {
		log.Printf("vip %s:%d (host %q): no endpoint matches profile %q + port", dstIP, dstPort, hostname, profile)
		_ = c.Close()
		return
	}
	g.dispatchConnEndpoint(c, dstIP, matchedPort, ep, hostname)
}

// tryDirectIPConn is the post-VIP fallback that dispatches inbound
// connections to ConnEndpointRuntime plugins whose endpoint hosts are
// IP literals (or hostnames whose resolved IP happens to land in the
// conn-index). Returns true when a matching endpoint claimed the
// connection so the caller skips wgRelay.
//
// Mirrors handlePostgresConn's index-then-dispatch pattern, but
// generalised: any endpoint whose body implements ConnRouter +
// whose plugin Runtime satisfies ConnEndpointRuntime is eligible.
// The clickhouse_native plugin uses this path when an operator binds
// it to bare-IP hosts (`hosts = ["172.17.0.1"]`) — those entries are
// skipped by dnsvip (no DNS query to intercept) so direct-IP dispatch
// is the only way they reach the plugin. profile filter prevents one
// device from punching into another profile's endpoint by IP.
func (g *Gateway) tryDirectIPConn(c net.Conn, dstIP string, dstPort uint16) bool {
	idx := g.connIdx.Load()
	if idx == nil {
		return false
	}
	pip := peerIP(c)
	profile := g.profileFor(pip)
	policy := g.Policy()
	candidates := idx.Lookup(dstIP)
	ep := pickEndpointForProfile(candidates, policy, profile)
	if ep == nil {
		return false
	}
	if _, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime); !ok {
		return false
	}
	g.dispatchConnEndpoint(c, dstIP, dstPort, ep, "")
	return true
}

// dispatchConnEndpoint hands one accepted conn to the endpoint's
// ConnEndpointRuntime. Shared between handleVIPConn and
// tryDirectIPConn; hostname is the agent-dialed name (set by the VIP
// path, empty for direct-IP). Closes c on a runtime-mismatch fail
// path; otherwise the plugin owns the conn lifetime.
func (g *Gateway) dispatchConnEndpoint(c net.Conn, dstIP string, dstPort uint16, ep *config.CompiledEndpoint, hostname string) {
	connRT, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime)
	if !ok {
		log.Printf("conn dispatch: endpoint %q plugin lacks ConnEndpointRuntime", ep.Name)
		_ = c.Close()
		return
	}
	pip := peerIP(c)
	profile := g.profileFor(pip)
	agentPip := g.agentIPFor(c)
	policy := g.Policy()
	mode := ep.Plugin.Type
	// Event Host carries the hostname when known (VIP path), else the
	// dst IP — keeps the dashboard's "where is this traffic going"
	// column populated for both dispatch shapes.
	eventHost := hostname
	if eventHost == "" {
		eventHost = dstIP
	}
	ch := &runtime.ConnHandle{
		Conn:         c,
		Endpoint:     ep,
		Policy:       policy,
		Profile:      profile,
		PeerIP:       pip,
		Secrets:      g.secrets,
		Blobs:        g.blobs,
		StateDir:     g.stateDir,
		DstPort:      dstPort,
		UpstreamHost: hostname,
		MintCert: func(host string) (*tls.Certificate, error) {
			return g.certs.mint(host)
		},
		DialUpstream: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Plugin passes the *real* upstream host:port — the
			// gateway's host network resolves it (the VIP only
			// exists inside the WG netstack; direct-IP dispatch
			// already has the real IP). When the endpoint declares
			// a tunnel, dialThrough routes the dial through the
			// TunnelManager; otherwise it falls back to the
			// gateway's direct dialer.
			if addr == "" {
				return nil, fmt.Errorf("conn dispatch: plugin gave empty upstream addr")
			}
			return g.dialThrough(ctx, ep, network, addr)
		},
		Emit: func(ev runtime.ConnEvent) {
			if g.sink == nil {
				return
			}
			g.sink.Emit(Event{
				Mode: mode, Family: ep.Family, Host: eventHost, AgentIP: agentPip,
				Method: ev.Verb, Path: ev.Summary,
				Action: ev.Action, Reason: ev.Reason,
				Facets:   ev.Facets,
				Endpoint: ep.Name, Rule: ev.Rule,
				Approver:     ev.Approver,
				ApproverType: ev.ApproverType,
				ApproverBy:   ev.ApproverBy,
			})
		},
		Approve: func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
			return g.runApproveChain(context.Background(), req.Stages, runApproveCtx{
				AgentIP: agentPip, Host: eventHost, Method: req.Verb, Path: req.Summary,
				Reason:   ifNotEmpty(req.Rule, func(r *config.CompiledRule) string { return r.Outcome.Reason }),
				Endpoint: ep, Rule: req.Rule, Profile: profile,
			})
		},
	}
	if err := connRT.HandleConn(context.Background(), ch); err != nil {
		if hostname != "" {
			log.Printf("%s vip %s (%s): %v", mode, dstIP, hostname, err)
		} else {
			log.Printf("%s direct %s:%d: %v", mode, dstIP, dstPort, err)
		}
	}
}

// handleDNSTCPConn dispatches an inbound TCP/53 flow to the dnsvip
// allocator's TCP serving loop. The udpDispatch closure handles the
// UDP variant; this is its TCP twin so DNS-over-TCP queries (large
// answers, axfr-style retries, or simply `dig +tcp`) keep working.
func (g *Gateway) handleDNSTCPConn(c net.Conn, dstIP string) {
	defer otelTrackConn("dns_tcp")()
	if dstIP == g.tailscaleIP {
		// Avoid self-relay loop: relayUpstream would dial ourselves.
		dstIP = ""
	}
	g.dnsvip.ServeTCP(c, dstIP)
}

// pickEndpointForProfile takes ConnIndex.Lookup candidates and returns
// the one whose name belongs to the device's profile. Returns nil when
// none of them do — caller should refuse the connection rather than
// silently route through an endpoint the device isn't supposed to
// touch. Single-tenant configs (no profile bound) fall through to
// the first candidate.
func pickEndpointForProfile(candidates []*config.CompiledEndpoint, policy *config.CompiledPolicy, profile string) *config.CompiledEndpoint {
	if len(candidates) == 0 {
		return nil
	}
	if policy == nil || profile == "" {
		return candidates[0]
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		return candidates[0]
	}
	for _, c := range candidates {
		if _, in := prof.Endpoints[c.Name]; in {
			return c
		}
	}
	return nil
}

func (g *Gateway) splice(c net.Conn, host string) {
	start := time.Now()
	up, err := g.dialer.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		log.Printf("dial %s: %v", host, err)
		g.emit(Event{Mode: "splice", Host: host, AgentIP: g.onboard.AgentIPFor(peerIP(c)), Action: "error", Reason: err.Error(), Ms: time.Since(start).Milliseconds()})
		return
	}
	defer func() { _ = up.Close() }()
	agentAddr := g.onboard.AgentIPFor(peerIP(c)) // capture BEFORE pipe — RemoteAddr() goes nil once netstack closes the conn
	in, out := pipeProgress(c, up, g.streamTracker(agentAddr, host))
	g.emit(Event{Mode: "splice", Host: host, AgentIP: agentAddr, Action: "allow", In: in, Out: out, Ms: time.Since(start).Milliseconds()})
}

// serveTSNetDirect handles a direct (non-PROXY) TLS connection in tsnet mode.
// These come from admins opening the dashboard, clawpatrol join, etc. We
// terminate TLS using our CA (minting a cert for whatever SNI the client
// sends) and then serve the dashboard HTTP mux over the decrypted connection.
func (g *Gateway) serveTSNetDirect(c net.Conn, mux http.Handler) {
	defer func() { _ = c.Close() }()
	host, prefix, err := peekSNI(c)
	conn := wrapPeek(c, prefix)
	if err != nil {
		// No SNI — client connected via IP literal (common during `clawpatrol join`
		// before the CA is trusted). Fall back to the server-side IP so mint() can
		// produce a cert with an IP SAN that Go's TLS stack will accept.
		if local := c.LocalAddr().String(); local != "" {
			if h, _, splitErr := net.SplitHostPort(local); splitErr == nil {
				host = h
			}
		}
		if host == "" {
			log.Printf("tsnet-direct: sni: %v (no fallback)", err)
			return
		}
	}
	cert, err := g.certs.mint(host)
	if err != nil {
		log.Printf("tsnet-direct: mint %s: %v", host, err)
		return
	}
	tc := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("tsnet-direct: tls %s: %v", host, err)
		return
	}
	defer func() { _ = tc.Close() }()
	_ = http.Serve(&oneShotListener{c: tc}, mux)
}

// serveTsnetDNSUDP pumps UDP/53 datagrams from the tsnet listener
// through dnsvip.HandlePacket. Used for whole-machine exit-node
// clients so the gateway allocates VIPs for intercepted hostnames
// before the client's TCP follow-up arrives. dstIP is always "" —
// the gateway IS the resolver on this path, so non-VIP A/AAAA fall
// through to synthIPResponse and other types hit relayUpstream's
// SERVFAIL guard (no self-relay loop).
func serveTsnetDNSUDP(pc net.PacketConn, vip *dnsvip.Allocator) {
	defer func() { _ = pc.Close() }()
	buf := make([]byte, 4<<10)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := vip.HandlePacket(buf[:n], "")
		if resp == nil {
			continue
		}
		_, _ = pc.WriteTo(resp, src)
	}
}

// wgRelay is the catch-all path: WG peer wants to talk to a host we
// don't MITM (plain HTTP, ssh, anything not on :443 or the dash port).
// Dials the real dst from the host network and pipes bytes both ways.
// Emits a sink Event so transparently-relayed flows show up in the
// dashboard request history alongside MITM traffic — without this,
// ssh / git-over-ssh / arbitrary-port connections went silent.
//
// Analytics are gated on the peer being a known device. The tsnet
// fallback handler catches every TCP forwarded through the gateway's
// exit-node advertisement, which includes stray probes from every
// other tailnet peer on the network. Without the gate, each new
// probing tailnet IP mints a synthetic "agent" row in the dashboard
// and the actions table fills up with thousands of phantom devices
// that never appear in the device list. The dial still runs for
// unknown peers (relay behavior unchanged); only the sink event is
// suppressed.
func (g *Gateway) wgRelay(c net.Conn, dstIP string, dstPort int) {
	defer func() { _ = c.Close() }()
	pip := peerIP(c)
	profile := g.profileFor(pip)
	agentPip := g.agentIPFor(c)
	known := g.onboard == nil || g.onboard.HasDevice(pip) || g.onboard.HasDevice(agentPip)
	host := fmt.Sprintf("%s:%d", dstIP, dstPort)
	start := time.Now()
	up, err := net.DialTimeout("tcp", net.JoinHostPort(dstIP, strconv.Itoa(dstPort)), 10*time.Second)
	if err != nil {
		if known {
			g.sink.Emit(Event{
				Mode: "relay", AgentIP: agentPip, Agent: profile,
				Host: host, Action: "deny", Reason: err.Error(),
				Ms: time.Since(start).Milliseconds(),
			})
		}
		return
	}
	defer func() { _ = up.Close() }()
	var tracker func(rx, tx int64)
	if known {
		tracker = g.streamTracker(agentPip, host)
	}
	rx, tx := pipeProgress(c, up, tracker)
	if known {
		g.sink.Emit(Event{
			Mode: "relay", AgentIP: agentPip, Agent: profile,
			Host: host, Action: "allow",
			In: rx, Out: tx,
			Ms: time.Since(start).Milliseconds(),
		})
	}
}

// streamTracker returns a pipeProgress onTick callback that feeds the
// per-agent activity sparkline with per-second byte deltas. Long-lived
// flows (ssh clone, websocket) need DURING-flight updates — sampleLoop
// reads BytesIn/Out at 1Hz and computes a delta, so a 10-minute flow
// without streaming track calls paints flat zeros until close. Returns
// nil when no agent IP / no registry — pipeProgress treats nil as
// "skip the ticker goroutine entirely".
func (g *Gateway) streamTracker(agentIP, host string) func(rx, tx int64) {
	if g.agents == nil || agentIP == "" {
		return nil
	}
	var lastRx, lastTx int64
	return func(rx, tx int64) {
		dRx := rx - lastRx
		dTx := tx - lastTx
		lastRx, lastTx = rx, tx
		if dRx == 0 && dTx == 0 {
			return
		}
		g.agents.track(agentIP, host, dRx, dTx)
	}
}
