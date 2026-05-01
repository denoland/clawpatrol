package main

// Plain WireGuard onboarder — embedded userspace WG device, no kernel
// module, no wg-quick, no shelled-out CLI. Each onboarded device
// receives a freshly-generated keypair + the gateway's pubkey + a
// peer-block addressed to a free IP from the configured subnet.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
)

type wireguardOnboarder struct {
	ts        Tailscale
	server    *WGServer // injected at gateway boot; set by setWGServer
	mu        sync.Mutex
	allocPath string
}

// setWGServer wires the boot-time WGServer into the onboarder. Called
// from main once the listener is up.
var globalWG *WGServer

func setWGServer(s *WGServer) { globalWG = s }

func (w *wireguardOnboarder) MintKey(ctx context.Context) (string, string, string, error) {
	if w.ts.WGEndpoint == "" || w.ts.WGSubnetCIDR == "" {
		return "", "", "", fmt.Errorf("wireguard not configured (set tailscale.wg_endpoint, wg_subnet_cidr)")
	}
	if globalWG == nil {
		return "", "", "", fmt.Errorf("wireguard server not started")
	}
	clientPrivB64, clientPubHex, _, err := wgGenKeypair()
	if err != nil {
		return "", "", "", err
	}
	ip, err := w.allocateIP()
	if err != nil {
		return "", "", "", err
	}
	if err := globalWG.AddPeer(clientPubHex, ip); err != nil {
		return "", "", "", fmt.Errorf("wg add peer: %w", err)
	}
	serverPub, err := globalWG.PublicKey()
	if err != nil {
		return "", "", "", fmt.Errorf("wg server pub: %w", err)
	}
	serverPubB64, err := hexToB64(serverPub)
	if err != nil {
		return "", "", "", err
	}
	// PostUp/PostDown rewrite /etc/resolv.conf so libc lookups flow
	// through the tunnel (UDP/53 → 1.1.1.1 → gateway UDP forwarder).
	// Avoiding `DNS =` because wg-quick needs resolvconf/openresolv
	// for that, which many minimal images lack. Backup-then-restore
	// keeps system DNS sane after `wg-quick down`.
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
PostUp = cp /etc/resolv.conf /etc/resolv.conf.clawall.bak 2>/dev/null; printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
PostDown = mv /etc/resolv.conf.clawall.bak /etc/resolv.conf 2>/dev/null || true

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, clientPrivB64, ip, serverPubB64, w.ts.WGEndpoint)
	return conf, "wireguard://" + w.iface(), ip, nil
}

func (w *wireguardOnboarder) iface() string {
	if w.ts.WGInterface != "" {
		return w.ts.WGInterface
	}
	return "clawall"
}

// allocateIP grabs the next free IP from WGSubnetCIDR, persisting the
// allocation map to disk so restarts don't double-assign.
func (w *wireguardOnboarder) allocateIP() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	used := w.loadAllocations()
	_, cidr, err := net.ParseCIDR(w.ts.WGSubnetCIDR)
	if err != nil {
		return "", err
	}
	first := cidr.IP.To4()
	for i := 2; i < 255; i++ {
		ip := net.IPv4(first[0], first[1], first[2], byte(i)).String()
		if !used[ip] {
			used[ip] = true
			w.saveAllocations(used)
			return ip, nil
		}
	}
	return "", fmt.Errorf("wireguard subnet %s exhausted", w.ts.WGSubnetCIDR)
}

func (w *wireguardOnboarder) allocFile() string {
	if w.allocPath != "" {
		return w.allocPath
	}
	dir := os.Getenv("CLAWALL_OAUTH_DIR")
	if dir == "" {
		dir = "/opt/clawall/oauth"
	}
	return filepath.Join(dir, "wg-allocations.json")
}

func (w *wireguardOnboarder) loadAllocations() map[string]bool {
	used := map[string]bool{}
	b, err := os.ReadFile(w.allocFile())
	if err == nil {
		_ = json.Unmarshal(b, &used)
	}
	return used
}

func (w *wireguardOnboarder) saveAllocations(used map[string]bool) {
	b, _ := json.MarshalIndent(used, "", "  ")
	_ = os.WriteFile(w.allocFile(), b, 0o600)
}

// wgGenPrivateHex returns a freshly-generated WG private key in hex
// (the format wireguard-go's IpcSet expects).
func wgGenPrivateHex() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// curve25519 clamping
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return hex.EncodeToString(b[:]), nil
}

// wgGenKeypair returns (privKeyB64, pubKeyHex, pubKeyB64).
// Client config files use base64 (`PrivateKey = …`); wireguard-go's
// IpcSet uses hex.
func wgGenKeypair() (string, string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		hex.EncodeToString(pub),
		base64.StdEncoding.EncodeToString(pub),
		nil
}

func hexToB64(h string) (string, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
