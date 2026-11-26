package main

import (
	"net/netip"
	"testing"
)

func TestPickEndpointIP(t *testing.T) {
	v4 := netip.MustParseAddr("10.55.0.2")
	v6 := netip.MustParseAddr("fd00::1")
	v6b := netip.MustParseAddr("fd00::2")
	v4in6 := netip.MustParseAddr("::ffff:10.55.0.2")

	for _, tc := range []struct {
		name         string
		ips          []netip.Addr
		have4, have6 bool
		want         netip.Addr
	}{
		{"both underlays prefer IPv4", []netip.Addr{v6, v4}, true, true, v4},
		{"IPv6 only record", []netip.Addr{v6}, true, true, v6},
		{"4-in-6 is unmapped", []netip.Addr{v4in6}, true, false, v4},
		{"no IPv4 underlay skips A records", []netip.Addr{v4, v6, v6b}, false, true, v6},
		{"no IPv6 underlay skips AAAA records", []netip.Addr{v6, v4}, true, false, v4},
	} {
		got, err := pickEndpointIP(tc.ips, tc.have4, tc.have6)
		if err != nil || got != tc.want {
			t.Errorf("%s: pickEndpointIP = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := pickEndpointIP(nil, true, true); err == nil {
		t.Error("no records: want an error")
	}
	if _, err := pickEndpointIP([]netip.Addr{v4}, false, true); err == nil {
		t.Error("IPv4 record without an IPv4 underlay: want an error")
	}
	if _, err := pickEndpointIP([]netip.Addr{v6}, true, false); err == nil {
		t.Error("IPv6 record without an IPv6 underlay: want an error")
	}
}

func TestParseBridgeAuthorizer(t *testing.T) {
	typ, name, err := parseBridgeAuthorizer("kubernetes_token_review/agents")
	if err != nil || typ != "kubernetes_token_review" || name != "agents" {
		t.Fatalf("parse = %q %q %v", typ, name, err)
	}
	for _, bad := range []string{"", "agents", "kubernetes_token_review/", "/agents", "oidc/agents"} {
		if _, _, err := parseBridgeAuthorizer(bad); err == nil {
			t.Errorf("parseBridgeAuthorizer(%q) expected error", bad)
		}
	}
}

func TestValidateRouteProto(t *testing.T) {
	for _, ok := range []string{defaultRouteProto, "1", "255", "static", "clawpatrol"} {
		if err := validateRouteProto(ok); err != nil {
			t.Errorf("validateRouteProto(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "  ", "0", "256", "-1"} {
		if err := validateRouteProto(bad); err == nil {
			t.Errorf("validateRouteProto(%q) expected error", bad)
		}
	}
}

func TestGatewayURLIsPlaintext(t *testing.T) {
	for u, want := range map[string]bool{
		"http://clawpatrol-api.clawpatrol.svc:8080": true,
		"HTTP://gateway.example.com":                true,
		"https://gateway.example.com":               false,
		"":                                          false,
	} {
		if got := gatewayURLIsPlaintext(u); got != want {
			t.Errorf("gatewayURLIsPlaintext(%q) = %t, want %t", u, got, want)
		}
	}
}

func TestBridgeEffectiveMTU(t *testing.T) {
	for _, tc := range []struct {
		enrolled int
		local    int
		want     int
	}{
		{enrolled: 1404, local: 1420, want: 1404},
		{enrolled: 1420, local: 1404, want: 1420},
		{enrolled: 0, local: 1420, want: 1420},
		{enrolled: 0, local: 1404, want: 1404},
		{enrolled: 1280, local: 1420, want: 1280},
		{enrolled: 65475, local: 1420, want: 65475},
		{enrolled: 576, local: 1420, want: 1420},
		{enrolled: 65476, local: 1420, want: 1420},
		{enrolled: -1, local: 1420, want: 1420},
	} {
		if got := bridgeEffectiveMTU(tc.enrolled, tc.local); got != tc.want {
			t.Errorf("bridgeEffectiveMTU(%d, %d) = %d, want %d", tc.enrolled, tc.local, got, tc.want)
		}
	}
}
