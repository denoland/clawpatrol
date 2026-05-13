package main

import "testing"

func TestIsLocalGatewayLoopbackLiterals(t *testing.T) {
	cases := []string{
		"http://localhost:9080",
		"http://127.0.0.1:9080",
		"http://0.0.0.0:9080",
		"https://[::1]:9080",
		"http://Localhost:9080", // case-insensitive
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			local, reason := isLocalGateway(u)
			if !local {
				t.Fatalf("expected %q to be local; reason=%q", u, reason)
			}
		})
	}
}

func TestIsLocalGatewaySchemelessLocalhost(t *testing.T) {
	// `clawpatrol join localhost:9080` (no scheme) — url.Parse lands
	// "localhost:9080" in u.Scheme + u.Opaque, but we still extract
	// "localhost" via the Host fallback.
	local, reason := isLocalGateway("localhost:9080")
	if !local {
		t.Fatalf("expected schemeless localhost to be flagged; reason=%q", reason)
	}
}

func TestIsLocalGatewayNonLocalIP(t *testing.T) {
	// 198.51.100.0/24 is IANA-reserved for documentation and never
	// assigned to real interfaces, so this test is stable across
	// machines.
	u := "http://198.51.100.42:9080"
	local, reason := isLocalGateway(u)
	if local {
		t.Fatalf("expected %q to be non-local; got reason %q", u, reason)
	}
}

func TestIsLocalGatewayMalformed(t *testing.T) {
	// Garbage in → non-local. We don't want a parse error to be
	// interpreted as "yes, this is the gateway host."
	for _, u := range []string{"", "http://", "::::not a url::::"} {
		local, _ := isLocalGateway(u)
		if local {
			t.Errorf("expected %q (malformed) to be non-local", u)
		}
	}
}
