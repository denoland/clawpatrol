//go:build linux

package main

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestExitNodePrefsByIP(t *testing.T) {
	mp, err := exitNodePrefs(&ipnstate.Status{}, "100.64.0.7")
	if err != nil {
		t.Fatalf("exitNodePrefs by IP: %v", err)
	}
	if !mp.ExitNodeIPSet {
		t.Fatalf("ExitNodeIPSet not set")
	}
	if got := mp.Prefs.ExitNodeIP; got != netip.MustParseAddr("100.64.0.7") {
		t.Fatalf("ExitNodeIP = %v, want 100.64.0.7", got)
	}
}

func newPeerKey() key.NodePublic { return key.NewNode().Public() }

func TestExitNodePrefsByHostname(t *testing.T) {
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			newPeerKey(): {
				HostName:     "clawpatrol-gateway",
				DNSName:      "clawpatrol-gateway.tail-abc.ts.net.",
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.7")},
			},
			newPeerKey(): {
				HostName:     "other-node",
				DNSName:      "other-node.tail-abc.ts.net.",
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.8")},
			},
		},
	}

	cases := []string{
		"clawpatrol-gateway",                  // bare hostname
		"CLAWPATROL-GATEWAY",                  // case-insensitive
		"clawpatrol-gateway.tail-abc.ts.net",  // FQDN sans dot
		"clawpatrol-gateway.tail-abc.ts.net.", // FQDN with trailing dot
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			mp, err := exitNodePrefs(st, name)
			if err != nil {
				t.Fatalf("exitNodePrefs(%q): %v", name, err)
			}
			if got := mp.Prefs.ExitNodeIP; got != netip.MustParseAddr("100.64.0.7") {
				t.Fatalf("got %v, want 100.64.0.7", got)
			}
		})
	}
}

func TestExitNodePrefsNoMatch(t *testing.T) {
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			newPeerKey(): {
				HostName:     "other-node",
				DNSName:      "other-node.tail-abc.ts.net.",
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.8")},
			},
		},
	}
	_, err := exitNodePrefs(st, "missing-host")
	if err == nil {
		t.Fatalf("expected error for missing peer")
	}
	if !strings.Contains(err.Error(), "no peer matched") {
		t.Fatalf("error %q does not mention `no peer matched`", err)
	}
}

func TestExitNodePrefsPeerWithoutIP(t *testing.T) {
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			newPeerKey(): {
				HostName: "pending-node",
				DNSName:  "pending-node.tail-abc.ts.net.",
			},
		},
	}
	_, err := exitNodePrefs(st, "pending-node")
	if err == nil || !strings.Contains(err.Error(), "no tailnet IP") {
		t.Fatalf("expected `no tailnet IP` error, got %v", err)
	}
}

func TestJoinAddrs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"empty", nil, ""},
		{"single", []string{"100.64.0.5/32"}, "100.64.0.5/32"},
		{"dual", []string{"100.64.0.5/32", "fd7a::5/128"}, "100.64.0.5/32, fd7a::5/128"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinAddrs(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
