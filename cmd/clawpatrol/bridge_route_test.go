package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParseDefaultRoute(t *testing.T) {
	r, err := parseDefaultRoute([]byte("default via 169.254.1.1 dev eth0 \n"))
	if err != nil || r.Via != "169.254.1.1" || r.Dev != "eth0" {
		t.Fatalf("parseDefaultRoute = %+v, %v", r, err)
	}
	r, err = parseDefaultRoute([]byte("default dev clawpatrol0 scope link\n"))
	if err != nil || r.Via != "" || r.Dev != "clawpatrol0" {
		t.Fatalf("parseDefaultRoute(no via) = %+v, %v", r, err)
	}
	if _, err := parseDefaultRoute(nil); err == nil {
		t.Fatal("empty output parsed")
	}
	r, err = parseDefaultRoute([]byte("default via 10.47.0.1 dev eth0 onlink\ndefault via 10.99.0.1 dev eth1 metric 100\n"))
	if err != nil || r != (linuxDefaultRoute{Via: "10.47.0.1", Dev: "eth0", OnLink: true}) {
		t.Fatalf("parseDefaultRoute(onlink) = %+v, %v", r, err)
	}
}

func TestUnderlayRoutingArgs(t *testing.T) {
	got := underlayTableArgs("-4", linuxDefaultRoute{Via: "169.254.1.1", Dev: "eth0"}, 111, "111")
	want := "ip -4 route replace default via 169.254.1.1 dev eth0 table 111 proto 111"
	if strings.Join(got, " ") != want {
		t.Fatalf("underlayTableArgs = %q, want %q", strings.Join(got, " "), want)
	}
	got = underlayTableArgs("-6", linuxDefaultRoute{Dev: "eth0"}, 111, "111")
	if slices.Contains(got, "via") {
		t.Fatalf("underlayTableArgs without a gateway = %q", got)
	}
	got = underlayTableArgs("-4", linuxDefaultRoute{Via: "10.47.0.1", Dev: "eth0", OnLink: true}, 111, "111")
	if got[len(got)-1] != "onlink" {
		t.Fatalf("underlayTableArgs lost onlink: %v", got)
	}

	rules := markRuleArgs("-4", 111, 111)
	if len(rules) != 2 {
		t.Fatalf("markRuleArgs returned %d rules", len(rules))
	}
	if got := strings.Join(rules[0], " "); got != "ip -4 rule add pref 90 fwmark 0x6f lookup main suppress_prefixlength 0" {
		t.Fatalf("suppress rule = %q", got)
	}
	if got := strings.Join(rules[1], " "); got != "ip -4 rule add pref 91 fwmark 0x6f lookup 111" {
		t.Fatalf("table rule = %q", got)
	}
}

func TestRuleShowHas(t *testing.T) {
	out := "0:\tfrom all lookup local\n" +
		"90:\tfrom all fwmark 0x6f lookup main suppress_prefixlength 0\n" +
		"91:\tfrom all fwmark 0x6f lookup 111\n" +
		"32766:\tfrom all lookup main\n"
	if !ruleShowHas(out, "90", 111) || !ruleShowHas(out, "91", 111) {
		t.Fatal("existing rules not found")
	}
	if ruleShowHas(out, "91", 112) {
		t.Fatal("rule with another mark matched")
	}
	if ruleShowHas(out, "9", 111) {
		t.Fatal("pref prefix matched another pref")
	}
}

func TestValidateBridgeFwmark(t *testing.T) {
	for _, ok := range []int{1, 111, 0x1000, 0xffffffff} {
		if err := validateBridgeFwmark(ok); err != nil {
			t.Errorf("validateBridgeFwmark(%d) = %v", ok, err)
		}
	}
	for _, bad := range []int{0, -1, 253, 254, 255, 0x100000000} {
		if err := validateBridgeFwmark(bad); err == nil {
			t.Errorf("validateBridgeFwmark(%d) accepted", bad)
		}
	}
}

func TestFirstDefaultRoute(t *testing.T) {
	out := []byte("default dev clawpatrol0 scope link \n" +
		"default via 10.244.0.1 dev eth0 \n" +
		"default dev lo proto 111 scope link metric 4294967295 \n")
	r, ok := firstDefaultRoute(out, "clawpatrol0", "lo")
	if !ok || r.Dev != "eth0" || r.Via != "10.244.0.1" {
		t.Fatalf("firstDefaultRoute = %+v, %t; want the eth0 route", r, ok)
	}
	if _, ok := firstDefaultRoute([]byte("default dev lo metric 4294967295\n"), "lo"); ok {
		t.Fatal("only a skipped route, but got one")
	}
	if got := strings.Join(fallbackDefaultArgs("111"), " "); got != "ip -4 route replace default dev lo metric 4294967295 proto 111" {
		t.Fatalf("fallbackDefaultArgs = %q", got)
	}
}

func TestBridgeTunnelSplitCIDRs(t *testing.T) {
	peer := netip.MustParseAddr("10.55.0.7")
	gw := netip.MustParseAddr("10.55.0.1")
	got := bridgeTunnelSplitCIDRs([]string{
		"10.244.1.0/16", // masked
		"10.244.0.0/16", // duplicate after masking
		"bad",           // skipped
		"10.55.0.0/24",  // contains a tunnel address
		"fd00:10::/64",  // no IPv6 underlay
		"10.96.0.0/12",
	}, []netip.Addr{peer, gw}, false)
	if fmt.Sprint(got) != "[10.244.0.0/16 10.96.0.0/12]" {
		t.Fatalf("got %v", got)
	}
	if got := bridgeTunnelSplitCIDRs([]string{"fd00:10::/64"}, nil, true); fmt.Sprint(got) != "[fd00:10::/64]" {
		t.Fatalf("IPv6 with an underlay: %v", got)
	}
}

func TestTunnelSplitRouteArgs(t *testing.T) {
	under := linuxDefaultRoute{Via: "10.0.1.97", Dev: "eth0", OnLink: true}
	for _, tc := range []struct {
		action, cidr, want string
	}{
		{"replace", "10.244.0.0/16", "ip -4 route replace 10.244.0.0/16 via 10.0.1.97 dev eth0 proto 111 metric 42760 onlink"},
		{"del", "10.244.0.0/16", "ip -4 route del 10.244.0.0/16 dev eth0 proto 111 metric 42760"},
		{"replace", "fd00:10::/64", "ip -6 route replace fd00:10::/64 via 10.0.1.97 dev eth0 proto 111 metric 42760 onlink"},
	} {
		got := strings.Join(tunnelSplitRouteArgs(tc.action, netip.MustParsePrefix(tc.cidr), under, "111"), " ")
		if got != tc.want {
			t.Fatalf("%s %s = %q, want %q", tc.action, tc.cidr, got, tc.want)
		}
	}
}
