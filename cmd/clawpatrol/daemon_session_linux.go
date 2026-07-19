//go:build linux

package main

// Per-session gVisor stack helpers. One stack per `clawpatrol run`
// session, bound to the daemon's transport-supplied local address
// (tsnet 100.x.x.x or WG /32 — the stack doesn't care which). All
// outbound TCP and UDP through the child's TUN flows out via
// transport.Dial.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// runStackTunMTU is the TUN MTU for the child's netns. Max IPv4
// packet size — wireguard-go (WG mode) and tsnet (Tailscale mode)
// handle path-MTU + fragmentation behind the transport, so the
// child-side TUN doesn't need to cap.
const runStackTunMTU = 65535

const runUDPIdleTimeout = 2 * time.Minute

// runUDPFlowLimit bounds endpoint, connection, and goroutine state per run
// session. 256 permits substantial DNS/QUIC concurrency while limiting a
// session to at most 512 checked-out 64 KiB relay buffers (32 MiB).
const runUDPFlowLimit = 256

var runUDPRelayBufferPool = sync.Pool{New: func() any {
	buf := make([]byte, runStackTunMTU)
	return &buf
}}

func getRunUDPRelayBuffer() []byte {
	return *runUDPRelayBufferPool.Get().(*[]byte)
}

func putRunUDPRelayBuffer(buf []byte) {
	buf = buf[:runStackTunMTU]
	runUDPRelayBufferPool.Put(&buf)
}

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
			tcp.NewProtocol, udp.NewProtocol,
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

// injectRunTunPacket takes ownership of pkt. InjectInbound is synchronous and
// does not consume the caller's reference, so every dispatch and drop path
// releases it here.
func injectRunTunPacket(ep *channel.Endpoint, version byte, pkt *stack.PacketBuffer) {
	defer pkt.DecRef()
	switch version {
	case 4:
		ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	case 6:
		ep.InjectInbound(header.IPv6ProtocolNumber, pkt)
	default:
		// Drop packets with an unknown IP version.
	}
}

// startTunBridge registers the outbound notification and starts the
// inbound read loop (TUN fd → gVisor InjectInbound).
func startTunBridge(tunFile *os.File, ep *channel.Endpoint) {
	br := &runTunBridge{tunFile: tunFile, ep: ep}
	ep.AddNotify(br)

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
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			injectRunTunPacket(ep, pkt[0]>>4, pkb)
		}
	}()
}

// enableTransportUDPForwarder installs gVisor's dual-stack UDP
// forwarder. gVisor owns packet parsing, checksums and full-tuple flow
// demultiplexing; each accepted endpoint is relayed as datagrams over
// one transport connection.
func enableTransportUDPForwarder(ctx context.Context, s *stack.Stack, transport daemonTransport, idleTimeout time.Duration) {
	enableTransportUDPForwarderWithLimit(ctx, s, transport, idleTimeout, runUDPFlowLimit)
}

func enableTransportUDPForwarderWithLimit(ctx context.Context, s *stack.Stack, transport daemonTransport, idleTimeout time.Duration, flowLimit int) {
	slots := make(chan struct{}, flowLimit)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, newTransportUDPProtocolHandler(ctx, s, transport, idleTimeout, slots))
}

// newRunUDPProtocolHandler borrows the stack-owned pkt only for the synchronous
// callback. CreateEndpoint must happen before the callback returns so its queue
// receives the endpoint's own packet clone.
func newRunUDPProtocolHandler(s *stack.Stack, handler udp.ForwarderHandler) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		return handler(udp.NewForwarderRequest(s, id, pkt))
	}
}

type udpDNSGateway interface {
	udpDNSGatewayAddr() netip.Addr
}

func udpDialAddr(transport daemonTransport, dstIP string, dstPort uint16) string {
	if gateway, ok := transport.(udpDNSGateway); ok && dstPort == 53 {
		dstIP = gateway.udpDNSGatewayAddr().String()
	}
	return net.JoinHostPort(dstIP, strconv.Itoa(int(dstPort)))
}

func newTransportUDPProtocolHandler(ctx context.Context, s *stack.Stack, transport daemonTransport, idleTimeout time.Duration, slots chan struct{}) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return newRunUDPProtocolHandler(s, func(req *udp.ForwarderRequest) bool {
		select {
		case slots <- struct{}{}:
		default:
			// Returning false lets gVisor generate the appropriate unreachable.
			return false
		}
		release := func() { <-slots }

		// CreateEndpoint must remain in the callback, but transport.Dial may
		// block for its full timeout and must not stall the sole TUN ingress
		// loop. Capture the request ID by value before starting the goroutine.
		id := req.ID()
		var wq waiter.Queue
		ep, terr := req.CreateEndpoint(&wq)
		if terr != nil {
			release()
			return true
		}
		local := gonet.NewUDPConn(&wq, ep)
		dstAddr := udpDialAddr(transport, id.LocalAddress.String(), id.LocalPort)
		go func() {
			dialCtx, cancel := context.WithTimeout(ctx, transportDialTimeout)
			defer cancel()
			remote, err := transport.Dial(dialCtx, "udp", dstAddr)
			if err != nil {
				// The callback has already returned true, so no ICMP unreachable
				// can be requested here without fabricating a packet. Closing the
				// endpoint avoids retaining a black hole and permits tuple redial.
				_ = local.Close()
				release()
				return
			}
			relayUDPDatagrams(ctx, local, remote, idleTimeout, release)
		}()
		return true
	})
}

func udpIdleRemaining(lastActivity int64, now time.Time, idleTimeout time.Duration) time.Duration {
	elapsed := now.Sub(time.Unix(0, lastActivity))
	if elapsed < 0 {
		return idleTimeout
	}
	return idleTimeout - elapsed
}

func relayUDPDatagrams(ctx context.Context, local, remote net.Conn, idleTimeout time.Duration, release func()) {
	defer release()
	closeBoth := func() {
		_ = local.Close()
		_ = remote.Close()
	}
	activity := make(chan struct{}, 1)
	done := make(chan struct{}, 1)
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	signalDone := func() {
		select {
		case done <- struct{}{}:
		default:
		}
	}
	copyDatagrams := func(dst, src net.Conn, boundRead bool) {
		buf := getRunUDPRelayBuffer()
		defer putRunUDPRelayBuffer(buf)
		for {
			if boundRead {
				now := time.Now()
				remaining := udpIdleRemaining(lastActivity.Load(), now, idleTimeout)
				if remaining <= 0 {
					signalDone()
					return
				}
				if err := src.SetReadDeadline(now.Add(remaining)); err != nil {
					signalDone()
					return
				}
			}
			n, err := src.Read(buf)
			if err != nil {
				if boundRead {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() &&
						udpIdleRemaining(lastActivity.Load(), time.Now(), idleTimeout) > 0 {
						// Activity in the opposite direction raced this deadline.
						// Recalculate from the shared timestamp and keep reading.
						continue
					}
				}
				signalDone()
				return
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				signalDone()
				return
			}
			lastActivity.Store(time.Now().UnixNano())
			select {
			case activity <- struct{}{}:
			default:
			}
		}
	}
	go copyDatagrams(remote, local, false)
	go copyDatagrams(local, remote, true)
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	defer closeBoth()
	resetFromLastActivity := func() bool {
		remaining := udpIdleRemaining(lastActivity.Load(), time.Now(), idleTimeout)
		if remaining <= 0 {
			return false
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(remaining)
		return true
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-timer.C:
			// A successful write can race delivery of timer.C. Re-read the
			// race-safe timestamp before deciding the flow is idle.
			if !resetFromLastActivity() {
				return
			}
		case <-activity:
			if !resetFromLastActivity() {
				return
			}
		}
	}
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
