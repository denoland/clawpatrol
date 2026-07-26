package main

import (
	"net/netip"
	"testing"
)

func TestPreferV4(t *testing.T) {
	v4 := netip.MustParseAddr("10.55.0.2")
	v6 := netip.MustParseAddr("fd00::1")
	v4in6 := netip.MustParseAddr("::ffff:10.55.0.2")

	if got, ok := preferV4([]netip.Addr{v6, v4}); !ok || got != v4 {
		t.Fatalf("preferV4([v6,v4]) = %v (ok=%v), want %v", got, ok, v4)
	}
	if got, ok := preferV4([]netip.Addr{v6}); !ok || got != v6 {
		t.Fatalf("preferV4(v6-only) = %v (ok=%v), want %v", got, ok, v6)
	}
	if got, ok := preferV4([]netip.Addr{v4in6}); !ok || !got.Is4() || got != v4 {
		t.Fatalf("preferV4(4-in-6) = %v (ok=%v), want unmapped %v", got, ok, v4)
	}
	if _, ok := preferV4(nil); ok {
		t.Fatal("preferV4(nil) should be ok=false")
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
