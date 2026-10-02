package main

// Destination policy for the relay paths — the ones that dial an
// address the agent chose rather than one an endpoint declared.
//
// Three paths take an agent's word for where to connect: wgRelay (the
// transparent TCP catch-all, reached once no endpoint claims the dst),
// relayUDP (the same for datagrams), and splice (the SNI passthrough
// under defaults.unknown_host = "passthrough", which dials the name out
// of the ClientHello). All three dial from the gateway host, which sits
// on networks the agent does not: the host's own loopback, the
// operator's LAN, and a cloud instance's metadata service at
// 169.254.169.254, whose credentials are the gateway's own.
//
// So a destination is classified before it is dialled, and the
// classification happens on the address that will actually be dialled.
// splice resolves the name itself and hands the dialer a literal: a
// check against one lookup followed by a dial that performs another is
// no check at all, because the second answer is the attacker's to
// choose.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"tailscale.com/net/tsaddr"
)

// relayDestRefusal names the class a destination was refused under. The
// class, not the address, is what an operator needs to see to know
// which knob answers it.
type relayDestRefusal struct {
	class string
	addr  netip.Addr
	// via is set when the refusal is for an address the dialled one
	// encodes rather than the dialled one itself — a 4via6 destination
	// carries an IPv4 inside an IPv6 the gateway would route to it.
	via netip.Addr
}

func (e *relayDestRefusal) Error() string {
	if e.via.IsValid() {
		return fmt.Sprintf("destination %s encodes %s (%s)", e.addr, e.via, e.class)
	}
	return fmt.Sprintf("destination %s is %s", e.addr, e.class)
}

func refuseDest(class string, addr netip.Addr) error {
	return &relayDestRefusal{class: class, addr: addr}
}

// Modes for defaults.relay_destinations.
const (
	relayDestPublic = "public"
	relayDestAny    = "any"
)

// relayDestPolicy is the decided form of defaults.relay_destinations
// and defaults.relay_allow_cidrs, plus the one thing the policy file
// does not state: whether the gateway is on a tailnet, which is what
// makes 100.64.0.0/10 a network it is supposed to reach.
//
// That last part is taken from the running transport and not from the
// config. A `tailscale {}` block is restart-only, so a hot reload that
// adds one declares a tailnet the process is not on — and reading the
// declaration would open CGNAT and Tailscale's ULA to an agent before
// any tailnet existed to reach.
type relayDestPolicy struct {
	mode    string
	allow   []netip.Prefix
	tailnet bool
}

// relayDestAllowed reports whether the gateway may dial ip on an
// agent's behalf.
//
// Under "public" the refused classes are the ones an agent has no
// business steering the gateway onto: the unspecified address, loopback,
// link-local (which is where 169.254.169.254 lives), multicast, and the
// private ranges — RFC1918 and the IPv6 ULA.
//
// Carrier-grade NAT is the awkward one, because 100.64.0.0/10 is also
// the whole of a tailnet's IPv4 space. A gateway with a `tailscale {}`
// block is meant to reach tailnet addresses, so for one the range is
// allowed along with Tailscale's ULA; for a WireGuard-only gateway,
// which has no tailnet to reach, it is refused with the rest.
//
// relay_allow_cidrs is consulted ahead of every class, which is how an
// operator keeps one internal subnet reachable through the relay
// without turning the policy off.
//
// An address that encodes another one is unwrapped and the address it
// encodes classified too, before any tailnet allowance: 4via6 sits
// inside Tailscale's ULA, so allowing that range wholesale would carry
// 169.254.169.254 through it. Every IPv4-in-IPv6 form gets the same
// treatment, because what such a dial reaches is the IPv4 inside and
// not the IPv6 the classification was handed.
//
// A zone is refused outright. `::%lo` is not the unspecified address as
// far as netip is concerned — IsUnspecified compares against the
// unzoned `::` — but it is the local system to the dialer, so a zoned
// destination is one whose dial target is not what any bit test says it
// is. An agent-selected destination has no business naming an interface
// of the gateway's.
func relayDestAllowed(ip netip.Addr, policy relayDestPolicy) error {
	if !ip.IsValid() {
		return refuseDest("not an address", ip)
	}
	// An IPv4-mapped IPv6 address dials the IPv4 it holds, so it is
	// classified as that address and not as an IPv6 one.
	ip = ip.Unmap()
	if policy.mode == relayDestAny {
		return nil
	}
	if ip.Zone() != "" {
		return refuseDest("scoped to an interface of this host", ip)
	}
	for _, p := range policy.allow {
		if p.Contains(ip) {
			return nil
		}
	}
	if inner, ok := embeddedV4(ip); ok {
		if err := relayDestAllowed(inner, policy); err != nil {
			var refusal *relayDestRefusal
			if errors.As(err, &refusal) {
				return &relayDestRefusal{class: refusal.class, addr: ip, via: inner}
			}
			return err
		}
	}
	if policy.tailnet && isTailnetAddr(ip) {
		return nil
	}
	switch {
	case ip.IsUnspecified():
		return refuseDest("the unspecified address", ip)
	case ip.IsLoopback():
		return refuseDest("loopback", ip)
	case ip.IsLinkLocalUnicast():
		return refuseDest("link-local", ip)
	case ip.IsInterfaceLocalMulticast():
		return refuseDest("interface-local multicast", ip)
	case ip.IsMulticast():
		return refuseDest("multicast", ip)
	case ip.IsPrivate():
		return refuseDest("private", ip)
	case tsaddr.CGNATRange().Contains(ip):
		return refuseDest("carrier-grade NAT", ip)
	case thisNetworkV4.Contains(ip):
		// 0.0.0.0/8 is "this network", and the dialer reads the whole
		// block the way it reads 0.0.0.0 — as the local system.
		return refuseDest("this network", ip)
	case ip == broadcastV4:
		return refuseDest("the broadcast address", ip)
	case teredoRange.Contains(ip):
		// Teredo obfuscates the IPv4 it carries, so it is refused as a
		// class rather than decoded and classified like the others.
		return refuseDest("Teredo", ip)
	}
	return nil
}

var (
	thisNetworkV4 = netip.MustParsePrefix("0.0.0.0/8")
	broadcastV4   = netip.MustParseAddr("255.255.255.255")
	teredoRange   = netip.MustParsePrefix("2001::/32")
	// v4Compatible is the deprecated ::a.b.c.d form, nat64Prefix the
	// well-known prefix RFC 6052 reserves, sixToFour the RFC 3056
	// encoding. Each carries an IPv4 address a dial would reach.
	v4Compatible = netip.MustParsePrefix("::/96")
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour    = netip.MustParsePrefix("2002::/16")
)

// embeddedV4 returns the IPv4 address ip encodes, for the forms whose
// encoding is plainly readable: Tailscale's 4via6, and the IPv6
// transition encodings that carry an IPv4 verbatim.
//
// The unspecified address and loopback are left out of the ::/96 case so
// they stay classified as themselves rather than as 0.0.0.0 and 0.0.0.1
// — the refusal names the class an operator has to act on.
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	if via := tsaddr.UnmapVia(ip); via != ip {
		return via, true
	}
	b := ip.As16()
	switch {
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case nat64Prefix.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case v4Compatible.Contains(ip) && !ip.IsUnspecified() && !ip.IsLoopback():
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// isTailnetAddr reports whether ip is one Tailscale assigns its nodes.
// The ChromeOS VM range is carved out of CGNAT and handed to something
// else, so it is not a tailnet address even though it sits inside the
// range Tailscale otherwise owns.
func isTailnetAddr(ip netip.Addr) bool {
	if tsaddr.CGNATRange().Contains(ip) {
		return !tsaddr.ChromeOSVMRange().Contains(ip)
	}
	return tsaddr.TailscaleULARange().Contains(ip)
}

// relayDestPolicy reads the live destination policy. An unset mode is
// "public": a gateway that declares nothing gets the classification,
// because the agent-chosen dial is the thing being bounded and an
// operator who has not thought about it has not opted into the host's
// private networks.
//
// The tailnet half is tsnetLC, which is non-nil only once a tsnet is up.
// A gateway still coming up classifies CGNAT as CGNAT for the moment
// before that, which refuses a tailnet destination rather than
// permitting a private one.
func (g *Gateway) relayDestPolicy() relayDestPolicy {
	p := relayDestPolicy{mode: relayDestPublic, tailnet: g.tsnetLC != nil}
	if policy := g.Policy(); policy != nil {
		if policy.RelayDestinations != "" {
			p.mode = policy.RelayDestinations
		}
		p.allow = policy.RelayAllowCIDRs
	}
	return p
}

// relayDestOK classifies a literal destination the agent named. Used by
// the paths that already hold an address: wgRelay and the UDP
// dispatchers.
func (g *Gateway) relayDestOK(dstIP string) error {
	ip, err := netip.ParseAddr(dstIP)
	if err != nil {
		return fmt.Errorf("destination %q is not an address: %w", dstIP, err)
	}
	return relayDestAllowed(ip, g.relayDestPolicy())
}

// relayDialTimeout bounds both halves of a resolve-then-dial. It
// matches the timeout the relay paths dialled with before they
// resolved separately.
const relayDialTimeout = 10 * time.Second

// dialRelayHost resolves host, classifies every address it resolved to,
// and dials the first one that passes — as a literal, so the connection
// lands on the address that was classified.
//
// A name is refused as soon as any of its addresses is, rather than
// after the allowed ones are exhausted. A name that answers with both a
// public address and 169.254.169.254 is a name steering the gateway at
// its metadata service; which of the two a given lookup happens to put
// first is not something to resolve by racing.
func (g *Gateway) dialRelayHost(ctx context.Context, host string, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, relayDialTimeout)
	defer cancel()
	addrs, err := g.resolveRelayHost(ctx, host)
	if err != nil {
		return nil, err
	}
	policy := g.relayDestPolicy()
	for _, ip := range addrs {
		if err := relayDestAllowed(ip, policy); err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
	}
	// Each address gets its own slice of the budget, so one that
	// black-holes cannot consume the whole of it and leave a working
	// address untried. Dialing literals in order is what classifying
	// them costs: the dialer can no longer race the families itself,
	// because it is never handed the name.
	var lastErr error
	per := relayDialTimeout / time.Duration(len(addrs))
	for _, ip := range addrs {
		attempt, cancelAttempt := context.WithTimeout(ctx, per)
		conn, err := g.dialer.DialContext(attempt, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		cancelAttempt()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address for %s", host)
	}
	return nil, lastErr
}

// relayResolver resolves a destination name to the addresses a dial
// would use. *net.Resolver satisfies it, which is what the gateway
// carries; the interface is what lets a test answer from a table.
type relayResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolveRelayHost turns host into the addresses a dial would use. A
// literal resolves to itself; a name goes through the gateway's
// resolver, which is the one `resolver` names when the operator set it.
func (g *Gateway) resolveRelayHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	res := g.resolver
	if res == nil {
		res = net.DefaultResolver
	}
	addrs, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}
	return addrs, nil
}
