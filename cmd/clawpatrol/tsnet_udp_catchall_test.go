package main

import (
	"net/netip"
	"testing"

	"github.com/denoland/clawpatrol/cmd/clawpatrol/dnsvip"
)

// tsnetUDPPeerOnboarded gates the non-DNS UDP relay so the gateway only
// relays for peers it has onboarded — not an open UDP proxy for any
// tailnet node that pins it as an exit node.
func TestTsnetUDPPeerOnboarded(t *testing.T) {
	r := newOnboardRegistry()
	r.knownDeviceIPs["100.64.0.2"] = true
	// tsnet flows often arrive on the peer's fd7a ULA; daemon register
	// maps it to the 100.x device via an alias.
	r.canonicalByAlias["fd7a:115c:a1e0::2"] = "100.64.0.2"
	g := &Gateway{onboard: r}

	cases := []struct {
		ip   string
		want bool
	}{
		{"100.64.0.2", true},          // onboarded device, direct
		{"fd7a:115c:a1e0::2", true},   // ULA alias → canonical onboarded
		{"100.99.99.99", false},       // unknown peer
		{"fd7a:115c:a1e0::99", false}, // unknown ULA
	}
	for _, c := range cases {
		if got := g.tsnetUDPPeerOnboarded(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("tsnetUDPPeerOnboarded(%s) = %v, want %v", c.ip, got, c.want)
		}
	}

	// Defensive: no registry and an invalid address never authorize.
	if (&Gateway{}).tsnetUDPPeerOnboarded(netip.MustParseAddr("100.64.0.2")) {
		t.Error("nil onboard registry must not authorize")
	}
	if g.tsnetUDPPeerOnboarded(netip.Addr{}) {
		t.Error("invalid address must not authorize")
	}
}

// tsnetUDPDisposition routes UDP/53 to dnsvip, drops UDP/443 (QUIC, so
// HTTPS falls back to the interceptable TCP path), relays other UDP for
// onboarded peers, and leaves the rest to tsnet's default handler.
func TestTsnetUDPDisposition(t *testing.T) {
	r := newOnboardRegistry()
	r.knownDeviceIPs["100.64.0.2"] = true
	g := &Gateway{onboard: r, dnsvip: &dnsvip.Allocator{}}

	onboarded := netip.MustParseAddr("100.64.0.2")
	stranger := netip.MustParseAddr("100.99.99.99")
	mk := func(port uint16) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), port)
	}

	cases := []struct {
		name string
		dst  netip.AddrPort
		src  netip.Addr
		want udpDisposition
	}{
		{"dns from onboarded", mk(53), onboarded, udpDNS},
		{"dns from stranger", mk(53), stranger, udpDNS}, // DNS is peer-agnostic
		{"quic from onboarded dropped", mk(443), onboarded, udpDrop},
		{"quic from stranger dropped", mk(443), stranger, udpDrop}, // never relay QUIC
		{"ntp from onboarded relayed", mk(123), onboarded, udpRelay},
		{"ntp from stranger passthrough", mk(123), stranger, udpPassthrough},
	}
	for _, c := range cases {
		if got := g.tsnetUDPDisposition(c.dst, c.src); got != c.want {
			t.Errorf("%s: disposition = %d, want %d", c.name, got, c.want)
		}
	}

	// With no dnsvip, UDP/53 isn't intercepted — but UDP/443 is still
	// dropped (QUIC blocking doesn't depend on dnsvip).
	g2 := &Gateway{onboard: r}
	if got := g2.tsnetUDPDisposition(mk(53), onboarded); got != udpRelay {
		t.Errorf("dns w/o dnsvip from onboarded: disposition = %d, want relay", got)
	}
	if got := g2.tsnetUDPDisposition(mk(443), onboarded); got != udpDrop {
		t.Errorf("quic w/o dnsvip: disposition = %d, want drop", got)
	}
}
