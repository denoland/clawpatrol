package main

import (
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
