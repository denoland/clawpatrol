package main

import (
	"net/netip"
	"testing"
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
