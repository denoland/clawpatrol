package config

import "testing"

func TestIsLoopbackBind(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		// Empty + any-interface forms must be treated as off-host —
		// they let the kernel pick any interface, including the
		// public one.
		{"", false},
		{":8080", false},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},

		// Loopback variants.
		{"127.0.0.1:8080", true},
		{"127.0.0.42:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"Localhost:8080", true},

		// LAN / public IPs.
		{"10.0.0.1:8080", false},
		{"192.168.1.10:8080", false},
		{"66.42.120.196:8080", false},

		// Bare hosts (no port) — older operator-written configs;
		// JoinHostPort roundtrip should still flag loopback IPs.
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"example.com:8080", false},
	}
	for _, tt := range tests {
		got := IsLoopbackBind(tt.addr)
		if got != tt.want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
