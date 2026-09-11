package main

import (
	"database/sql"
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

func newTestDNSVIP(t *testing.T) *dnsvip.Allocator {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE dnsvip_allocations (id INTEGER PRIMARY KEY, hostname TEXT, v4 TEXT, v6 TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	a, err := dnsvip.New(db, dnsvip.DefaultCIDR4, dnsvip.DefaultCIDR6)
	if err != nil {
		t.Fatalf("dnsvip.New: %v", err)
	}
	return a
}

// tsnetUDPDisposition: UDP/53 → dnsvip; UDP/443 → drop for every
// destination (QUIC is never inspected, so HTTPS must take the TCP
// MITM path); other UDP from an onboarded peer → relay; the rest →
// tsnet's default handler.
func TestTsnetUDPDisposition(t *testing.T) {
	r := newOnboardRegistry()
	r.knownDeviceIPs["100.64.0.2"] = true
	g := &Gateway{onboard: r, dnsvip: newTestDNSVIP(t)}

	onboarded := netip.MustParseAddr("100.64.0.2")
	stranger := netip.MustParseAddr("100.99.99.99")
	vip := netip.MustParseAddr("10.78.1.2") // inside DefaultCIDR4 → intercepted host
	pub := netip.MustParseAddr("8.8.8.8")   // public → pass-through host
	mk := netip.AddrPortFrom

	cases := []struct {
		name string
		dst  netip.AddrPort
		src  netip.Addr
		want udpDisposition
	}{
		{"dns onboarded", mk(pub, 53), onboarded, udpDNS},
		{"dns stranger", mk(pub, 53), stranger, udpDNS},
		{"quic to intercepted VIP dropped", mk(vip, 443), onboarded, udpDrop},
		{"quic to intercepted VIP dropped (stranger)", mk(vip, 443), stranger, udpDrop},
		{"quic to pass-through dropped too", mk(pub, 443), onboarded, udpDrop},
		{"quic to pass-through dropped for stranger", mk(pub, 443), stranger, udpDrop},
		{"ntp onboarded relayed", mk(pub, 123), onboarded, udpRelay},
		{"ntp stranger passthrough", mk(pub, 123), stranger, udpPassthrough},
	}
	for _, c := range cases {
		if got := g.tsnetUDPDisposition(c.dst, c.src); got != c.want {
			t.Errorf("%s: disposition = %d, want %d", c.name, got, c.want)
		}
	}

	// The QUIC drop does not depend on the VIP table: it holds with
	// no dnsvip at all.
	g2 := &Gateway{onboard: r}
	if got := g2.tsnetUDPDisposition(mk(vip, 443), onboarded); got != udpDrop {
		t.Errorf("443 w/o dnsvip from onboarded: disposition = %d, want drop", got)
	}
}

// udpPortDisposition is the one port decision both transports consume:
// the tsnet catch-all through tsnetUDPDisposition, the WireGuard
// forwarder and the Linux run daemon through refuseUDPPort (their
// pre-endpoint gate) plus the udpDNS check in runGateway's udpDispatch.
// Pin the table, then check every consumer agrees with it port by port
// so the QUIC refusal can never hold on one transport and not the other.
func TestUDPPortDisposition(t *testing.T) {
	want := map[uint16]udpDisposition{
		53:    udpDNS,
		443:   udpDrop,
		0:     udpRelay,
		123:   udpRelay, // NTP
		853:   udpRelay, // DoQ is not QUIC-on-443; it relays like any UDP
		4433:  udpRelay, // alternate QUIC ports are not refused (documented)
		8443:  udpRelay, // https authority on :8443 is MITM'd on TCP only
		5353:  udpRelay, // mDNS
		65535: udpRelay,
	}
	for port, d := range want {
		if got := udpPortDisposition(port); got != d {
			t.Errorf("udpPortDisposition(%d) = %d, want %d", port, got, d)
		}
	}

	r := newOnboardRegistry()
	r.knownDeviceIPs["100.64.0.2"] = true
	g := &Gateway{onboard: r, dnsvip: newTestDNSVIP(t)}
	onboarded := netip.MustParseAddr("100.64.0.2")
	stranger := netip.MustParseAddr("100.99.99.99")
	for _, dst := range []netip.Addr{
		netip.MustParseAddr("10.78.1.2"), // VIP
		netip.MustParseAddr("8.8.8.8"),   // public
		netip.MustParseAddr("2001:db8::1"),
	} {
		for port := range want {
			refused := refuseUDPPort(port)
			if refused != (udpPortDisposition(port) == udpDrop) {
				t.Errorf("refuseUDPPort(%d) = %v disagrees with udpPortDisposition", port, refused)
			}
			for _, src := range []netip.Addr{onboarded, stranger} {
				got := g.tsnetUDPDisposition(netip.AddrPortFrom(dst, port), src)
				if (got == udpDrop) != refused {
					t.Errorf("tsnetUDPDisposition(%s:%d from %s) = %d but refuseUDPPort = %v: transports disagree",
						dst, port, src, got, refused)
				}
				if udpPortDisposition(port) == udpDNS && got != udpDNS {
					t.Errorf("tsnetUDPDisposition(%s:%d from %s) = %d, want udpDNS", dst, port, src, got)
				}
			}
		}
	}
}
