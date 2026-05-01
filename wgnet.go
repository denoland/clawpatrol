package main

// Embedded userspace WireGuard server. No kernel module, no wg-quick,
// no /etc/wireguard, no systemd. The clawall binary IS the WG endpoint.
//
// Lifecycle:
//   - StartWGServer parses Tailscale config block (control=wireguard),
//     boots a wireguard-go device backed by a netstack TUN. Peers are
//     added via AddPeer(pubkey, allowed-ip) from the onboarder.
//   - EnablePromiscuousForwarder turns the netstack into an L3 sink:
//     SYNs to ANY destination IP land in our handler, carrying the
//     original (dst-ip, dst-port). Mirrors unclaw's smoltcp setup
//     (set_any_ip + dynamic listener pool) so peers don't need
//     /etc/hosts pinning — agents hit real api.anthropic.com and the
//     gateway dispatches by port.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
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

// netTun is our own wireguard-go tun.Device backed by a gVisor stack +
// channel.Endpoint. We can't use golang.zx2c4.com/wireguard/tun/netstack
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
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(stack.Options{
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

func (t *netTun) File() *os.File              { return nil }
func (t *netTun) Name() (string, error)       { return "clawall-wg", nil }
func (t *netTun) MTU() (int, error)           { return t.mtu, nil }
func (t *netTun) Events() <-chan wgtun.Event  { return t.events }
func (t *netTun) BatchSize() int              { return 1 }

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
	publicKey string // hex-encoded, derived from the private key at boot
	peerFile  string
}

// StartWGServer brings up a userspace WG endpoint listening on
// 0.0.0.0:<ListenPort>. Server private key is read from disk; if
// missing, generated and persisted at <stateDir>/wg-server.key.
func StartWGServer(ts Tailscale, stateDir string) (*WGServer, error) {
	if ts.WGSubnetCIDR == "" {
		return nil, fmt.Errorf("wireguard: wg_subnet_cidr required")
	}
	listenPort := 51820
	if ts.WGEndpoint != "" {
		if _, p, err := net.SplitHostPort(ts.WGEndpoint); err == nil {
			fmt.Sscanf(p, "%d", &listenPort)
		}
	}

	// Server key: persisted hex-encoded so restarts keep the same pub.
	keyPath := stateDir + "/wg-server.key"
	priv, err := loadOrGenWGKey(keyPath)
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
	srv := &WGServer{tun: tun, dev: dev, serverIP: serverIP, publicKey: pub, peerFile: stateDir + "/wg-peers.json"}
	// Replay persisted (pubkey → ip) pairs into the in-memory device
	// so reboots don't strand existing clients.
	for pubkey, ip := range loadPeers(srv.peerFile) {
		_ = dev.IpcSet(fmt.Sprintf(
			"public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n",
			pubkey, ip))
	}
	return srv, nil
}

func loadPeers(path string) map[string]string {
	out := map[string]string{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func savePeers(path string, peers map[string]string) error {
	b, _ := json.MarshalIndent(peers, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// AddPeer registers a peer (after admin approval). Idempotent — same
// pubkey overwrites previous AllowedIPs. Persists the (pubkey → ip)
// mapping to disk so the gateway can replay registrations on restart;
// wireguard-go peers are in-memory only.
func (s *WGServer) AddPeer(pubkeyHex, peerIP string) error {
	cfg := fmt.Sprintf(
		"public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n",
		pubkeyHex, peerIP,
	)
	if err := s.dev.IpcSet(cfg); err != nil {
		return err
	}
	peers := loadPeers(s.peerFile)
	peers[pubkeyHex] = peerIP
	return savePeers(s.peerFile, peers)
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
	// Each session gets a goroutine that proxies to the real dst via
	// the host's UDP stack. We don't try to MITM UDP, just relay.
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

// relayUDP shuttles datagrams between a netstack UDP conn (peer side)
// and the real upstream over the host's network. Both directions run
// until one half closes or 60s of idle.
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

// PublicKey returns the server's WG pubkey (hex) — handed out to
// every onboarded client. wireguard-go's IpcGet exposes peer pubkeys
// (each [Peer] block starts with `public_key=`), NOT the server's
// own. We derive ours from the saved private key at boot.
func (s *WGServer) PublicKey() (string, error) {
	if s.publicKey == "" {
		return "", fmt.Errorf("server publicKey not initialized")
	}
	return s.publicKey, nil
}

func loadOrGenWGKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	// Generate a fresh X25519 private key. wireguard-go expects 64-char
	// lowercase hex (not base64) on the IPC channel.
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
