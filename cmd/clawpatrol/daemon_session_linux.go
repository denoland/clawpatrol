//go:build linux

package main

// Per-session gVisor stack helpers. One stack per `clawpatrol run`
// session, bound to the daemon's transport-supplied local address
// (tsnet 100.x.x.x or WG /32 — the stack doesn't care which). All
// outbound TCP and UDP through the child's TUN flows out via
// transport.Dial.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// runStackTunMTU is the TUN MTU for the child's netns. Max IPv4
// packet size — wireguard-go (WG mode) and tsnet (Tailscale mode)
// handle path-MTU + fragmentation behind the transport, so the
// child-side TUN doesn't need to cap.
const runStackTunMTU = 65535

// newRunStack creates a gVisor TCP/IP stack bound to localIP, which
// is the transport's underlay address (tsnet 100.x.x.x or wg /32).
// Promiscuous + spoofing enabled so the stack accepts inbound
// packets destined to ANY address — the child's traffic carries
// real-world dst IPs that don't match localIP.
func newRunStack(localIP netip.Addr) (*stack.Stack, *channel.Endpoint, error) {
	ep := channel.New(netstackQueueSize, uint32(runStackTunMTU), "")
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
		},
		HandleLocal: false,
	})
	sackOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)
	rackOpt := tcpip.TCPRecovery(0)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rackOpt)
	ccOpt := tcpip.CongestionControlOption("reno")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)
	minRTOOpt := tcpip.TCPMinRTOOption(time.Second)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &minRTOOpt)
	rxBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBuf)
	txBuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 6 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &txBuf)

	if e := s.CreateNIC(1, ep); e != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", e)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(localIP.AsSlice()).WithPrefix(),
	}
	if e := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); e != nil {
		return nil, nil, fmt.Errorf("AddProtocolAddress: %v", e)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	if e := s.SetPromiscuousMode(1, true); e != nil {
		return nil, nil, fmt.Errorf("SetPromiscuousMode: %v", e)
	}
	if e := s.SetSpoofing(1, true); e != nil {
		return nil, nil, fmt.Errorf("SetSpoofing: %v", e)
	}
	return s, ep, nil
}

// runTunBridge pumps packets between the raw TUN fd and gVisor's
// channel endpoint. Implements channel.Notification for the outbound
// (gVisor→TUN) direction.
type runTunBridge struct {
	tunFile *os.File
	ep      *channel.Endpoint
}

func (b *runTunBridge) WriteNotify() {
	for {
		pkt := b.ep.Read()
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		_, _ = b.tunFile.Write(view.AsSlice())
	}
}

// startTunBridge registers the outbound notification and starts the
// inbound read loop (TUN fd → gVisor InjectInbound). IPv4 UDP is
// intercepted before injection and forwarded directly via the
// transport so DNS / quic-style flows work without a UDP forwarder
// inside the per-session gVisor stack.
func startTunBridge(tunFile *os.File, ep *channel.Endpoint, transport daemonTransport) {
	br := &runTunBridge{tunFile: tunFile, ep: ep}
	ep.AddNotify(br)
	uf := &runUDPForwarder{
		transport: transport,
		tunFile:   tunFile,
		flows:     map[udpFlowKey]net.Conn{},
	}

	go func() {
		buf := make([]byte, runStackTunMTU)
		for {
			n, err := tunFile.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			// Intercept IPv4 UDP before injecting into gVisor TCP stack.
			if pkt[0]>>4 == 4 && n > 20 && pkt[9] == 17 {
				uf.handle(pkt)
				continue
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			switch pkt[0] >> 4 {
			case 4:
				ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
			case 6:
				ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
			default:
				pkb.DecRef()
			}
		}
	}()
}

// runUDPForwarder maintains per-flow transport UDP connections for
// the child netns. Each unique (srcIP:srcPort → dstIP:dstPort)
// 4-tuple gets one transport.Dial("udp", ...) conn.
type runUDPForwarder struct {
	transport daemonTransport
	tunFile   *os.File
	mu        sync.Mutex
	flows     map[udpFlowKey]net.Conn
}

type udpFlowKey struct {
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
}

func (f *runUDPForwarder) handle(pkt []byte) {
	ihl := int(pkt[0]&0xf) * 4
	if len(pkt) < ihl+8 {
		return
	}
	var srcIP, dstIP [4]byte
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])
	srcPort := uint16(pkt[ihl])<<8 | uint16(pkt[ihl+1])
	dstPort := uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3])
	udpLen := int(pkt[ihl+4])<<8 | int(pkt[ihl+5])
	if udpLen < 8 || ihl+udpLen > len(pkt) {
		return
	}
	payload := pkt[ihl+8 : ihl+udpLen]

	key := udpFlowKey{srcIP, dstIP, srcPort, dstPort}

	f.mu.Lock()
	conn, ok := f.flows[key]
	if !ok {
		dstAddr := fmt.Sprintf("%d.%d.%d.%d:%d",
			dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort)
		var err error
		conn, err = f.transport.Dial(context.Background(), "udp", dstAddr)
		if err != nil {
			f.mu.Unlock()
			return
		}
		f.flows[key] = conn
		go func() {
			f.readResponses(conn, dstIP, srcIP, dstPort, srcPort)
			f.mu.Lock()
			delete(f.flows, key)
			f.mu.Unlock()
			_ = conn.Close()
		}()
	}
	f.mu.Unlock()

	_, _ = conn.Write(payload)
}

func (f *runUDPForwarder) readResponses(conn net.Conn, srcIP, dstIP [4]byte, srcPort, dstPort uint16) {
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = f.tunFile.Write(buildUDPPacket(srcIP, dstIP, srcPort, dstPort, buf[:n]))
	}
}

// buildUDPPacket constructs a raw IPv4+UDP packet. UDP checksum is zero
// (optional for IPv4; Linux accepts these from TUN devices).
func buildUDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)
	pkt[0] = 0x45 // IPv4, IHL=5
	pkt[2] = byte(ipLen >> 8)
	pkt[3] = byte(ipLen)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	cs := ipv4Checksum(pkt[:20])
	pkt[10] = byte(cs >> 8)
	pkt[11] = byte(cs)
	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)
	pkt[24] = byte(udpLen >> 8)
	pkt[25] = byte(udpLen)
	// pkt[26:28] = 0 (checksum omitted)
	copy(pkt[28:], payload)
	return pkt
}

func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// transportDialTimeout bounds the upstream transport.Dial while the
// child's SYN is left pending. Well below typical client connect
// timeouts, so a slow transport surfaces as our RST rather than the
// client giving up first.
const transportDialTimeout = 15 * time.Second

// enableTransportTCPForwarder installs a promiscuous TCP forwarder on
// s. Every connection dials the original destination via
// transport.Dial. In tsnet mode the transport routes through the
// exit-node-pinned tsnet.Server (the gateway sees original dst via
// RegisterFallbackTCPHandler). In WG mode the transport's gVisor
// stack dials the WG netstack directly.
//
// The upstream dial happens BEFORE the child-side handshake is
// completed: CreateEndpoint sends the SYN-ACK, so accepting first
// would make the child's connect() succeed unconditionally and turn
// every unreachable destination into connect-then-hang. Tunnel-backed
// endpoints depend on connect() failing fast — getaddrinfo iterates
// A/AAAA answers (and Happy Eyeballs races them) only when the
// previous attempt is refused, never when it hangs (#765). While the
// dial is in flight the SYN stays pending; the forwarder dedupes
// retransmitted SYNs for the same 4-tuple until Complete is called.
func enableTransportTCPForwarder(s *stack.Stack, transport daemonTransport) {
	fwd := tcp.NewForwarder(s, 1<<20, 16384, func(req *tcp.ForwarderRequest) {
		id := req.ID()
		dstAddr := net.JoinHostPort(id.LocalAddress.String(),
			fmt.Sprintf("%d", id.LocalPort))

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), transportDialTimeout)
			defer cancel()
			remote, err := transport.Dial(ctx, "tcp", dstAddr)
			if err != nil {
				req.Complete(true) // RST — refuse, don't accept-and-hang
				return
			}
			var wq waiter.Queue
			ep, terr := req.CreateEndpoint(&wq)
			if terr != nil {
				req.Complete(true)
				_ = remote.Close()
				return
			}
			req.Complete(false)
			local := gonet.NewTCPConn(&wq, ep)
			defer func() { _ = local.Close() }()
			defer func() { _ = remote.Close() }()
			tsnetBiRelay(local, remote)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}
