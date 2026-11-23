package main

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// mintDevice runs the server side of `clawpatrol join` for one device.
func mintDevice(t *testing.T, join JoinConfig, reuseIP string) (conf, ip string) {
	t.Helper()
	conf, _, ip, err := (&wireguardOnboarder{ts: join}).MintKey(context.Background(), reuseIP, false)
	if err != nil {
		t.Fatalf("MintKey(reuse %q): %v", reuseIP, err)
	}
	return conf, ip
}

// pubkeyForIP returns the single wg_peers key for ip.
func pubkeyForIP(t *testing.T, g *Gateway, ip string) string {
	t.Helper()
	if n := wgPeerRowsForIP(t, g, ip); n != 1 {
		t.Fatalf("wg_peers rows for %s = %d, want 1", ip, n)
	}
	var pub string
	if err := g.db.QueryRow(`SELECT pubkey FROM wg_peers WHERE ip = ?`, ip).Scan(&pub); err != nil {
		t.Fatalf("read pubkey for %s: %v", ip, err)
	}
	return pub
}

// A new device gets the next address, a config with its IPv4 and IPv6
// addresses, and a peer on the live device.
func TestMintKeyNewDevices(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	wg, join := startTestWGServer(t, g, "10.55.0.0/24")

	conf, ip := mintDevice(t, join, "")
	if ip != "10.55.0.2" {
		t.Fatalf("first device ip = %s, want 10.55.0.2", ip)
	}
	if !strings.Contains(conf, "Address = 10.55.0.2/32, fd77::2/128\n") {
		t.Fatalf("config has the wrong addresses:\n%s", conf)
	}
	if !strings.Contains(conf, "Endpoint = gateway.example.com:") {
		t.Fatalf("config has no endpoint from public_url:\n%s", conf)
	}
	allowed := allowedIPsForKey(t, wg, pubkeyForIP(t, g, ip))
	if !slices.Contains(allowed, "10.55.0.2/32") || !slices.Contains(allowed, "fd77::2/128") {
		t.Fatalf("device allowed IPs = %v, want 10.55.0.2/32 and fd77::2/128", allowed)
	}

	if _, ip2 := mintDevice(t, join, ""); ip2 != "10.55.0.3" {
		t.Fatalf("second device ip = %s, want 10.55.0.3", ip2)
	}
}

// Re-running join from the same machine keeps the address and replaces the
// key, on the device and in wg_peers.
func TestMintKeyRejoinKeepsAddress(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	wg, join := startTestWGServer(t, g, "10.55.0.0/24")
	_, ip := mintDevice(t, join, "")
	oldPub := pubkeyForIP(t, g, ip)
	mintDevice(t, join, "") // another device, so the newest row is not ip

	conf, again := mintDevice(t, join, ip)
	if again != ip {
		t.Fatalf("re-join ip = %s, want %s", again, ip)
	}
	if !strings.Contains(conf, "Address = "+ip+"/32, fd77::2/128\n") {
		t.Fatalf("re-join config has the wrong addresses:\n%s", conf)
	}
	newPub := pubkeyForIP(t, g, ip)
	if newPub == oldPub {
		t.Fatal("re-join kept the old key")
	}
	if got := allowedIPsForKey(t, wg, oldPub); len(got) != 0 {
		t.Fatalf("old key still has allowed IPs %v on the device", got)
	}
	if got := allowedIPsForKey(t, wg, newPub); !slices.Contains(got, ip+"/32") {
		t.Fatalf("new key allowed IPs = %v, want %s/32", got, ip)
	}
}

// In a subnet wider than /24, the config carries the IPv6 address for the
// full host bits.
func TestMintKeyWideSubnetIPv6(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	seedWGPeerRows(t, g, "10.55.1.1")
	_, join := startTestWGServer(t, g, "10.55.0.0/16")

	conf, ip := mintDevice(t, join, "")
	if ip != "10.55.1.2" {
		t.Fatalf("device ip = %s, want 10.55.1.2 (next after the newest row)", ip)
	}
	if !strings.Contains(conf, "Address = 10.55.1.2/32, fd77::102/128\n") {
		t.Fatalf("config has the wrong addresses:\n%s", conf)
	}
}

// A gateway restart replays persisted peers with both allowed IPs.
func TestStartWGServerReplaysPersistedPeers(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	pub := hex.EncodeToString([]byte(strings.Repeat("r", 32)))
	if _, err := g.db.Exec(`INSERT INTO wg_peers (pubkey, ip, added_ns) VALUES (?, ?, 1)`, pub, "10.55.1.2"); err != nil {
		t.Fatalf("seed wg_peers: %v", err)
	}
	wg, _ := startTestWGServer(t, g, "10.55.0.0/16")

	allowed := allowedIPsForKey(t, wg, pub)
	if !slices.Contains(allowed, "10.55.1.2/32") || !slices.Contains(allowed, "fd77::102/128") {
		t.Fatalf("replayed allowed IPs = %v, want 10.55.1.2/32 and fd77::102/128", allowed)
	}
}
