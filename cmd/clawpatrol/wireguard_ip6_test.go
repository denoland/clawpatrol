package main

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

// The fd77:: mapping round-trips through canonicalPeerIP's inverse for every
// supported prefix width.
func TestWG6FromV4RoundTrip(t *testing.T) {
	cases := []struct {
		prefix, v4, v6 string
	}{
		{"10.55.0.0/24", "10.55.0.1", "fd77::1"},
		{"10.55.0.0/24", "10.55.0.254", "fd77::fe"},
		{"10.55.0.128/25", "10.55.0.130", "fd77::82"},
		{"10.55.0.0/20", "10.55.3.7", "fd77::307"},
		{"10.55.0.0/16", "10.55.1.2", "fd77::102"},
		{"10.55.0.0/16", "10.55.255.254", "fd77::fffe"},
	}
	for _, tc := range cases {
		prefix := netip.MustParsePrefix(tc.prefix)
		v4 := netip.MustParseAddr(tc.v4)
		got := wg6FromV4(prefix, v4)
		if got.String() != tc.v6 {
			t.Errorf("wg6FromV4(%s, %s) = %s, want %s", tc.prefix, tc.v4, got, tc.v6)
		}
		back, ok := wgV4FromV6(prefix, got)
		if !ok || back != v4 {
			t.Errorf("wgV4FromV6(%s, %s) = %s, %t, want %s", tc.prefix, got, back, ok, tc.v4)
		}
	}
}

// For a /24 the mapping must stay fd77::<last-octet>, so existing clients and
// wg-quick configs keep working.
func TestWG6FromV4KeepsSlash24Mapping(t *testing.T) {
	prefix := netip.MustParsePrefix("10.55.0.0/24")
	for i := 1; i < 255; i++ {
		v4 := netip.AddrFrom4([4]byte{10, 55, 0, byte(i)})
		var want [16]byte
		want[0], want[1], want[15] = 0xfd, 0x77, byte(i)
		if got := wg6FromV4(prefix, v4); got != netip.AddrFrom16(want) {
			t.Fatalf("wg6FromV4(%s) = %s, want %s", v4, got, netip.AddrFrom16(want))
		}
	}
}

// Addresses in different /24s of a wider prefix get different IPv6 addresses.
func TestWG6FromV4NoCollisionsBeyondSlash24(t *testing.T) {
	prefix := netip.MustParsePrefix("10.55.0.0/16")
	seen := map[netip.Addr]netip.Addr{}
	for third := 0; third < 4; third++ {
		for fourth := 0; fourth < 256; fourth++ {
			v4 := netip.AddrFrom4([4]byte{10, 55, byte(third), byte(fourth)})
			v6 := wg6FromV4(prefix, v4)
			if prev, ok := seen[v6]; ok {
				t.Fatalf("%s and %s both map to %s", prev, v4, v6)
			}
			seen[v6] = v4
		}
	}
}

func TestWGV4FromV6RejectsForeignAddresses(t *testing.T) {
	prefix := netip.MustParsePrefix("10.55.0.0/24")
	for _, s := range []string{
		"fd7a:115c:a1e0::1", // Tailscale ULA
		"fd77::1:2",         // host bits outside a /24
		"fd77:1::5",         // non-zero middle bytes
		"::ffff:10.55.0.5",  // v4-mapped
		"2001:db8::5",
	} {
		if v4, ok := wgV4FromV6(prefix, netip.MustParseAddr(s)); ok {
			t.Errorf("wgV4FromV6(%s) = %s, want not ok", s, v4)
		}
	}
}

func TestCanonicalPeerIPUsesServerPrefix(t *testing.T) {
	prev := globalWG
	t.Cleanup(func() { globalWG = prev })

	globalWG = nil
	if got := canonicalPeerIP("fd77::5"); got != "10.55.0.5" {
		t.Fatalf("early-boot canonicalPeerIP(fd77::5) = %s, want 10.55.0.5", got)
	}
	globalWG = &WGServer{prefix: netip.MustParsePrefix("10.60.0.0/16")}
	if got := canonicalPeerIP("fd77::102"); got != "10.60.1.2" {
		t.Fatalf("canonicalPeerIP(fd77::102) = %s, want 10.60.1.2", got)
	}
	if got := canonicalPeerIP("fd7a:115c:a1e0::1"); got != "fd7a:115c:a1e0::1" {
		t.Fatalf("non-wg address changed to %s", got)
	}
	if got := canonicalPeerIP("10.60.1.2"); got != "10.60.1.2" {
		t.Fatalf("v4 address changed to %s", got)
	}
}

// Peers allocated past the first /24 of a wider subnet get distinct IPv6
// allowed IPs on the live device.
func TestAllocatePeerIPv6UniqueInWideSubnet(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	prevDB, prevWG := globalDB, globalWG
	globalDB = g.db
	join := JoinConfig{WGSubnetCIDR: "10.55.0.0/16", WGListenPort: freeUDPPort(t), PublicURL: "https://gateway.example.com"}
	wg, err := StartWGServer(join)
	if err != nil {
		globalDB = prevDB
		t.Skipf("WGServer unavailable in this environment: %v", err)
	}
	setWGServer(wg)
	t.Cleanup(func() {
		wg.dev.Close()
		globalWG, globalDB = prevWG, prevDB
	})

	for i := range 300 {
		var key [32]byte
		key[0], key[1] = byte(i>>8), byte(i)
		pub := hex.EncodeToString(key[:])
		if _, err := wg.allocatePeer(join, pub); err != nil {
			t.Fatalf("allocate peer %d: %v", i, err)
		}
	}
	uapi, err := wg.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	seen := map[string]bool{}
	v6 := 0
	for _, line := range strings.Split(uapi, "\n") {
		ip, ok := strings.CutPrefix(line, "allowed_ip=fd77:")
		if !ok {
			continue
		}
		if seen[ip] {
			t.Fatalf("duplicate IPv6 allowed IP fd77:%s", ip)
		}
		seen[ip] = true
		v6++
	}
	if v6 != 300 {
		t.Fatalf("IPv6 allowed IPs = %d, want 300", v6)
	}
}

// seedWGPeerRows inserts wg_peers rows in order, each newer than the last.
func seedWGPeerRows(t *testing.T, g *Gateway, ips ...string) {
	t.Helper()
	for i, ip := range ips {
		pub := hex.EncodeToString([]byte(strings.Repeat(string(rune('a'+i)), 32)))
		if _, err := g.db.Exec(`INSERT INTO wg_peers (pubkey, ip, added_ns) VALUES (?, ?, ?)`, pub, ip, int64(i+1)); err != nil {
			t.Fatalf("seed wg_peers %s: %v", ip, err)
		}
	}
}

func TestAllocateWGPeerIPNextFit(t *testing.T) {
	cases := []struct {
		name    string
		subnet  string
		rows    []string
		release []string
		want    string
	}{
		{name: "empty table", subnet: "10.55.0.0/24", want: "10.55.0.2"},
		{name: "after the newest row", subnet: "10.55.0.0/24", rows: []string{"10.55.0.3"}, want: "10.55.0.4"},
		{name: "released address not reused first", subnet: "10.55.0.0/24", rows: []string{"10.55.0.2", "10.55.0.3"}, release: []string{"10.55.0.2"}, want: "10.55.0.4"},
		{name: "wraps at the end", subnet: "10.55.0.0/24", rows: []string{"10.55.0.254"}, want: "10.55.0.2"},
		{name: "wraps past used addresses", subnet: "10.55.0.0/24", rows: []string{"10.55.0.2", "10.55.0.254"}, want: "10.55.0.3"},
		{name: "newest outside subnet", subnet: "10.55.0.0/24", rows: []string{"10.99.0.9"}, want: "10.55.0.2"},
		{name: "crosses a /24 boundary", subnet: "10.55.0.0/16", rows: []string{"10.55.0.255"}, want: "10.55.1.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newEnrollmentTestGateway(t)
			seedWGPeerRows(t, g, tc.rows...)
			for _, ip := range tc.release {
				if _, err := g.db.Exec(`DELETE FROM wg_peers WHERE ip = ?`, ip); err != nil {
					t.Fatalf("release %s: %v", ip, err)
				}
			}
			got, err := allocateWGPeerIPLocked(g.db, JoinConfig{WGSubnetCIDR: tc.subnet})
			if err != nil {
				t.Fatalf("allocate: %v", err)
			}
			if got != tc.want {
				t.Fatalf("allocated %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAllocateWGPeerIPExhausted(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	seedWGPeerRows(t, g, "10.55.0.2", "10.55.0.3", "10.55.0.4", "10.55.0.5", "10.55.0.6")
	if ip, err := allocateWGPeerIPLocked(g.db, JoinConfig{WGSubnetCIDR: "10.55.0.0/29"}); err == nil {
		t.Fatalf("allocated %s from a full /29, want an exhausted error", ip)
	}
}
