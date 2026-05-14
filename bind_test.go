package main

import "testing"

func TestBindIsPublic(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Public (or unable-to-classify-as-private).
		{"", true},               // ":port" — all interfaces
		{"0.0.0.0", true},        // explicit IPv4 wildcard
		{"::", true},             // IPv6 wildcard
		{"1.2.3.4", true},        // public v4
		{"8.8.8.8", true},        // public v4
		{"2001:db8::1", true},    // public v6 (documentation prefix, but globally routable in classifier terms)
		{"gw.example.com", true}, // hostname — assumed public
		{"deno.clawpatrol.dev", true},

		// Private — loopback.
		{"127.0.0.1", false},
		{"127.0.0.42", false},
		{"::1", false},

		// Private — RFC1918.
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.254", false},
		{"192.168.1.1", false},

		// Not private — gap between 172.16/12 and 172.32.
		{"172.32.0.1", true},

		// IPv6 ULA (RFC 4193).
		{"fd00::1", false},
		{"fd12:3456:789a::1", false},

		// Link-local.
		{"169.254.1.1", false},
		{"fe80::1", false},

		// CGNAT (Tailscale's range).
		{"100.64.0.1", false},
		{"100.100.100.100", false},
		{"100.127.255.254", false},
		// 100.128.0.0 is OUTSIDE CGNAT — public.
		{"100.128.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			if got := bindIsPublic(tc.host); got != tc.want {
				t.Errorf("bindIsPublic(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}
