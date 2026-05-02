package main

// Plain WireGuard control plane — embedded userspace WG endpoint + L3
// forwarder + per-device onboarder. The clawpatrol binary IS the WG
// endpoint; no kernel module, no wg-quick, no /etc/wireguard, no
// systemd, no /etc/hosts pinning on clients.
//
// Architecture:
//   - StartWGServer boots a wireguard-go device backed by our own
//     gVisor netstack TUN (HandleLocal=false — see netTun comment).
//   - EnablePromiscuousForwarder turns the netstack into an L3 sink:
//     SYNs/datagrams to ANY destination IP land in the caller's
//     dispatcher with the original 4-tuple. Mirrors unclaw's smoltcp
//     `set_any_ip` + dynamic listener pool model.
//   - wireguardOnboarder mints a fresh keypair + allocates a /32 from
//     the configured subnet for each new device, registers the peer
//     with the live device, hands back a wg-quick conf.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netTun is our own wireguard-go tun.Device backed by a gVisor stack +
// channel.Endpoint. Can't use golang.zx2c4.com/wireguard/tun/netstack
// because it builds the stack with HandleLocal=true; combined with
// promiscuous mode that flips every inbound src into "local source"
// territory, which the IPv4 layer drops at line 893 of network/ipv4.go.
// HandleLocal=false here is the whole point.
type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan wgtun.Event
	incomingPacket chan []byte
	mtu            int
	closed         bool
}

func newNetTUN(addr netip.Addr, mtu int) (*netTun, error) {
	dev := &netTun{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
			HandleLocal:        false,
		}),
		events:         make(chan wgtun.Event, 10),
		incomingPacket: make(chan []byte, 1024),
		mtu:            mtu,
	}
	dev.ep.AddNotify(&epNotify{dev: dev})
	if e := dev.stack.CreateNIC(1, dev.ep); e != nil {
		return nil, fmt.Errorf("CreateNIC: %v", e)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}
	if e := dev.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); e != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %v", e)
	}
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	dev.events <- wgtun.EventUp
	return dev, nil
}

type epNotify struct{ dev *netTun }

func (n *epNotify) WriteNotify() {
	pkt := n.dev.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	b := view.AsSlice()
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case n.dev.incomingPacket <- cp:
	default:
		// drop on full queue; wireguard-go will keep up under normal load
	}
}

func (t *netTun) File() *os.File             { return nil }
func (t *netTun) Name() (string, error)      { return "clawpatrol-wg", nil }
func (t *netTun) MTU() (int, error)          { return t.mtu, nil }
func (t *netTun) Events() <-chan wgtun.Event { return t.events }
func (t *netTun) BatchSize() int             { return 1 }

func (t *netTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n := copy(bufs[0][offset:], pkt)
	sizes[0] = n
	return 1, nil
}

func (t *netTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		// diag: log TCP SYNs to non-443/8080 ports so we can see if
		// packets reach the netstack but the forwarder doesn't fire.
		if len(pkt) >= 40 && (pkt[0]>>4) == 4 && pkt[9] == 6 {
			ihl := int(pkt[0]&0xf) * 4
			if len(pkt) >= ihl+14 {
				flags := pkt[ihl+13]
				dstPort := (uint16(pkt[ihl+2]) << 8) | uint16(pkt[ihl+3])
				if flags&0x02 != 0 && dstPort != 443 && dstPort != 80 && dstPort != 8080 {
					srcIP := net.IP(pkt[12:16]).String()
					dstIP := net.IP(pkt[16:20]).String()
					log.Printf("wg-syn: %s → %s:%d", srcIP, dstIP, dstPort)
				}
			}
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		switch pkt[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		default:
			pkb.DecRef()
		}
	}
	return len(bufs), nil
}

func (t *netTun) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	t.stack.RemoveNIC(1)
	t.stack.Close()
	close(t.events)
	close(t.incomingPacket)
	return nil
}

type WGServer struct {
	tun       *netTun
	dev       *device.Device
	serverIP  netip.Addr
	publicKey string  // hex-encoded, derived from the private key at boot
	db        *sql.DB // wg_peers row store
}

// globalWG / globalDB are set at gateway boot. The onboarder reads
// them to register peers + allocate IPs without a circular dependency
// on the gateway struct.
var (
	globalWG *WGServer
	globalDB *sql.DB
)

func setWGServer(s *WGServer) { globalWG = s }
func setDB(d *sql.DB)         { globalDB = d }

// StartWGServer brings up a userspace WG endpoint listening on
// 0.0.0.0:<ListenPort>. Server private key is read from disk; if
// missing, generated and persisted at <stateDir>/wg-server.key.
func StartWGServer(ts GatewayConfig, stateDir string) (*WGServer, error) {
	if ts.WGSubnetCIDR == "" {
		return nil, fmt.Errorf("wireguard: wg_subnet_cidr required")
	}
	listenPort := 51820
	if ts.WGEndpoint != "" {
		if _, p, err := net.SplitHostPort(ts.WGEndpoint); err == nil {
			fmt.Sscanf(p, "%d", &listenPort)
		}
	}

	priv, err := loadOrGenWGKey(stateDir + "/wg-server.key")
	if err != nil {
		return nil, err
	}

	prefix, err := netip.ParsePrefix(ts.WGSubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("wg subnet: %w", err)
	}
	serverIP := prefix.Addr().Next() // x.x.x.1

	tun, err := newNetTUN(serverIP, 1420)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "[wg] "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", priv, listenPort)); err != nil {
		return nil, fmt.Errorf("wg ipc: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("wg up: %w", err)
	}
	pub, err := wgPubFromPrivHex(priv)
	if err != nil {
		return nil, fmt.Errorf("derive pub: %w", err)
	}
	srv := &WGServer{tun: tun, dev: dev, serverIP: serverIP, publicKey: pub, db: globalDB}
	// Replay persisted (pubkey → ip) pairs into the in-memory device
	// so reboots don't strand existing clients.
	for pubkey, ip := range srv.loadPeers() {
		_ = dev.IpcSet(fmt.Sprintf(
			"public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n",
			pubkey, ip))
	}
	return srv, nil
}

// AddPeer registers a peer (after admin approval). Idempotent — same
// pubkey overwrites previous AllowedIPs. Any prior peer holding this
// WG-side IP is REVOKED from the wg-go trie + the wg_peers table so
// only one /32-owner exists. Accumulated ghost peers from previous
// onboards otherwise win the trie race on restart and silently drop
// the current client's traffic.
func (s *WGServer) AddPeer(pubkeyHex, peerIP string) error {
	if s.db != nil {
		rows, err := s.db.Query("SELECT pubkey FROM wg_peers WHERE ip = ? AND pubkey != ?", peerIP, pubkeyHex)
		if err == nil {
			var stale []string
			for rows.Next() {
				var k string
				if rows.Scan(&k) == nil {
					stale = append(stale, k)
				}
			}
			rows.Close()
			for _, k := range stale {
				_ = s.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", k))
				_, _ = s.db.Exec("DELETE FROM wg_peers WHERE pubkey = ?", k)
			}
		}
	}
	if err := s.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n",
		pubkeyHex, peerIP,
	)); err != nil {
		return err
	}
	if s.db != nil {
		_, err := s.db.Exec(`
			INSERT INTO wg_peers (pubkey, ip, added_ns) VALUES (?, ?, ?)
			ON CONFLICT(pubkey) DO UPDATE SET ip = excluded.ip
		`, pubkeyHex, peerIP, time.Now().UnixNano())
		return err
	}
	return nil
}

// EnablePromiscuousForwarder turns the netstack into an L3 sink.
// SYNs to ANY destination IP/port reach `handler`; the wrapped net.Conn
// already carries the original 4-tuple via TransportEndpointID. Mirrors
// unclaw/smoltcp's set_any_ip + dynamic listener pool model.
//
// Caller dispatches by dstPort (e.g. 443 → MITM, dash port → mux,
// else → transparent relay to the real upstream IP).
func (s *WGServer) EnablePromiscuousForwarder(handler func(c net.Conn, dstIP string, dstPort uint16)) error {
	st := s.tun.stack
	if err := st.SetPromiscuousMode(1, true); err != nil {
		return fmt.Errorf("set promiscuous: %v", err)
	}
	if err := st.SetSpoofing(1, true); err != nil {
		return fmt.Errorf("set spoofing: %v", err)
	}
	fwd := tcp.NewForwarder(st, 0, 1024, func(req *tcp.ForwarderRequest) {
		id := req.ID()
		var wq waiter.Queue
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			req.Complete(true)
			return
		}
		req.Complete(false)
		c := gonet.NewTCPConn(&wq, ep)
		go handler(c, id.LocalAddress.String(), id.LocalPort)
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	// UDP forwarder — DNS, QUIC, etc. need to reach real upstreams.
	udpFwd := udp.NewForwarder(st, func(req *udp.ForwarderRequest) bool {
		id := req.ID()
		var wq waiter.Queue
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			return true
		}
		go relayUDP(gonet.NewUDPConn(&wq, ep),
			id.LocalAddress.String(), id.LocalPort)
		return true
	})
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return nil
}

// PublicKey returns the server's WG pubkey (hex) — handed out to every
// onboarded client. wireguard-go's IpcGet exposes peer pubkeys, NOT
// the server's own; we derive ours from the saved private key at boot.
func (s *WGServer) PublicKey() (string, error) {
	if s.publicKey == "" {
		return "", fmt.Errorf("server publicKey not initialized")
	}
	return s.publicKey, nil
}

// relayUDP shuttles datagrams between a netstack UDP conn (peer side)
// and the real upstream over the host's network. Both directions run
// until one half closes.
func relayUDP(c net.Conn, dstIP string, dstPort uint16) {
	defer c.Close()
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort)))
	if err != nil {
		return
	}
	up, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if _, err := up.Write(buf[:n]); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := up.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if _, err := c.Write(buf[:n]); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
}

func (s *WGServer) loadPeers() map[string]string {
	out := map[string]string{}
	if s.db == nil {
		return out
	}
	rows, err := s.db.Query("SELECT pubkey, ip FROM wg_peers")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, ip string
		if rows.Scan(&k, &ip) == nil {
			out[k] = ip
		}
	}
	return out
}

func loadOrGenWGKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	priv, err := wgGenPrivateHex()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(strings.TrimSuffix(path, "/wg-server.key"), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(priv), 0o600); err != nil {
		return "", err
	}
	return priv, nil
}

func wgPubFromPrivHex(privHex string) (string, error) {
	priv, err := hex.DecodeString(strings.TrimSpace(privHex))
	if err != nil || len(priv) != 32 {
		return "", fmt.Errorf("invalid wg priv hex")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

// wgGenPrivateHex returns a fresh WG private key in hex (the format
// wireguard-go's IpcSet expects).
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

// wgGenKeypair returns (privKeyB64, pubKeyHex, pubKeyB64). Client conf
// files use base64; wireguard-go's IpcSet uses hex.
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

type wireguardOnboarder struct {
	ts     GatewayConfig
	server *WGServer // injected at gateway boot; set by setWGServer
	mu     sync.Mutex
}

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
PostUp = cp /etc/resolv.conf /etc/resolv.conf.clawpatrol.bak 2>/dev/null; printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
PostDown = mv /etc/resolv.conf.clawpatrol.bak /etc/resolv.conf 2>/dev/null || true

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
	return "clawpatrol"
}

// allocateIP grabs the next free IP from WGSubnetCIDR. The allocation
// set is derived from wg_peers (one row per active peer); a fresh DB
// = a fresh subnet. AddPeer commits the (pubkey, ip) row.
func (w *wireguardOnboarder) allocateIP() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	used := map[string]bool{}
	if globalDB != nil {
		rows, err := globalDB.Query("SELECT ip FROM wg_peers")
		if err == nil {
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					used[ip] = true
				}
			}
			rows.Close()
		}
	}
	_, cidr, err := net.ParseCIDR(w.ts.WGSubnetCIDR)
	if err != nil {
		return "", err
	}
	first := cidr.IP.To4()
	for i := 2; i < 255; i++ {
		ip := net.IPv4(first[0], first[1], first[2], byte(i)).String()
		if !used[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("wireguard subnet %s exhausted", w.ts.WGSubnetCIDR)
}
