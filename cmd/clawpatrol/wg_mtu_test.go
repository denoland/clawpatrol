package main

import "testing"

func TestWGMTUForPath(t *testing.T) {
	for _, c := range []struct{ in, want int }{
		{1500, 1420}, // ethernet
		{9000, 1420}, // jumbo: never above the default
		{1280, 1200}, // tailscale
		{1300, 1220},
		{1000, 1000}, // never below the floor
	} {
		if got := wgMTUForPath(c.in); got != c.want {
			t.Errorf("wgMTUForPath(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseRouteDev(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"100.101.102.103 dev tailscale0 table 52 src 100.64.0.1 uid 1000 \\    cache", "tailscale0"},
		{"1.2.3.4 via 192.168.1.1 dev eth0 src 192.168.1.5 uid 0 \\    cache", "eth0"},
		{"RTNETLINK answers: Network is unreachable", ""},
		{"", ""},
	} {
		if got := parseRouteDev(c.in); got != c.want {
			t.Errorf("parseRouteDev(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWGMTUFromEnv(t *testing.T) {
	t.Setenv(wgMTUEnv, "")
	if _, set, err := wgMTUFromEnv(); set || err != nil {
		t.Fatalf("unset: set=%v err=%v", set, err)
	}
	t.Setenv(wgMTUEnv, "1200")
	if n, set, err := wgMTUFromEnv(); !set || err != nil || n != 1200 {
		t.Fatalf("1200: n=%d set=%v err=%v", n, set, err)
	}
	for _, bad := range []string{"abc", "900", "9000"} {
		t.Setenv(wgMTUEnv, bad)
		if _, set, err := wgMTUFromEnv(); !set || err == nil {
			t.Fatalf("%q: expected an error", bad)
		}
	}
}
