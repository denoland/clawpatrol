//go:build linux

package main

// Tests for the per-session gVisor TCP forwarder. A second gVisor
// stack stands in for the child's netns: the two channel endpoints
// are cross-pumped, so a gonet dial on the client stack behaves like
// the child's connect() through the TUN.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
)

// fakeTransport implements daemonTransport with a pluggable Dial.
type fakeTransport struct {
	mu     sync.Mutex
	dialed []string
	dial   func(network, addr string) (net.Conn, error)
}

func (f *fakeTransport) Dial(_ context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, network+"|"+addr)
	f.mu.Unlock()
	return f.dial(network, addr)
}
func (f *fakeTransport) LocalAddr() netip.Addr { return netip.MustParseAddr("100.64.0.5") }
func (f *fakeTransport) BootWarning() string   { return "" }
func (f *fakeTransport) Close() error          { return nil }

func (f *fakeTransport) dialedAddrs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.dialed)
}

type recordingNetworkDispatcher struct {
	protocols []tcpip.NetworkProtocolNumber
}

func (d *recordingNetworkDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	d.protocols = append(d.protocols, protocol)
}

func (*recordingNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func TestInjectRunTunPacketReleasesCallerReference(t *testing.T) {
	tests := []struct {
		name         string
		version      byte
		wantProtocol tcpip.NetworkProtocolNumber
	}{
		{name: "IPv4", version: 4, wantProtocol: header.IPv4ProtocolNumber},
		{name: "IPv6", version: 6, wantProtocol: header.IPv6ProtocolNumber},
		{name: "unknown", version: 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := channel.New(1, uint32(runStackTunMTU), "")
			dispatcher := &recordingNetworkDispatcher{}
			ep.Attach(dispatcher)
			releases := 0
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{OnRelease: func() { releases++ }})

			injectRunTunPacket(ep, tt.version, pkt)

			if got := pkt.ReadRefs(); got != 0 {
				t.Fatalf("PacketBuffer refs = %d, want 0", got)
			}
			if releases != 1 {
				t.Fatalf("PacketBuffer releases = %d, want exactly 1", releases)
			}
			if tt.wantProtocol == 0 {
				if len(dispatcher.protocols) != 0 {
					t.Fatalf("unknown packet dispatched as protocols %v", dispatcher.protocols)
				}
				return
			}
			if !slices.Equal(dispatcher.protocols, []tcpip.NetworkProtocolNumber{tt.wantProtocol}) {
				t.Fatalf("dispatched protocols = %v, want [%d]", dispatcher.protocols, tt.wantProtocol)
			}
		})
	}
}

func TestRunUDPProtocolHandlerDoesNotCloneRejectedPacket(t *testing.T) {
	s := stack.New(stack.Options{})
	t.Cleanup(s.Close)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	handler := newRunUDPProtocolHandler(s, func(*udp.ForwarderRequest) bool { return false })

	if handler(stack.TransportEndpointID{}, pkt) {
		t.Fatal("handler accepted rejected request")
	}
	if got := pkt.ReadRefs(); got != 1 {
		t.Fatalf("PacketBuffer refs after rejection = %d, want original caller ref only", got)
	}
	pkt.DecRef()
	if got := pkt.ReadRefs(); got != 0 {
		t.Fatalf("PacketBuffer refs after caller release = %d, want 0", got)
	}
}

func TestRunUDPProtocolHandlerFlowLimitRejectionDoesNotClonePacket(t *testing.T) {
	s := stack.New(stack.Options{})
	t.Cleanup(s.Close)
	ft := &fakeTransport{dial: func(string, string) (net.Conn, error) {
		t.Fatal("flow-limit rejection must not dial")
		return nil, context.Canceled
	}}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	handler := newTransportUDPProtocolHandler(context.Background(), s, ft, time.Minute, slots)

	if handler(stack.TransportEndpointID{}, pkt) {
		t.Fatal("handler accepted request with no available flow slots")
	}
	if got := pkt.ReadRefs(); got != 1 {
		t.Fatalf("PacketBuffer refs after flow-limit rejection = %d, want original caller ref only", got)
	}
	pkt.DecRef()
	if got := pkt.ReadRefs(); got != 0 {
		t.Fatalf("PacketBuffer refs after caller release = %d, want 0", got)
	}
}

// pump copies outbound packets from src's channel endpoint into dst's
// inbound path until ctx is done.
func pump(ctx context.Context, src, dst *channel.Endpoint) {
	for {
		pkt := src.ReadContext(ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		raw := view.AsSlice()
		if len(raw) == 0 {
			continue
		}
		proto := header.IPv4ProtocolNumber
		if raw[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}
		np := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(slices.Clone(raw)),
		})
		dst.InjectInbound(proto, np)
		np.DecRef()
	}
}

// newForwarderHarness builds the daemon-side stack (with the
// transport TCP forwarder installed) and a client stack wired to it,
// returning the client stack for gonet dials.
func newForwarderHarness(t *testing.T, transport daemonTransport) *stack.Stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, srvEp, err := newRunStack(netip.MustParseAddr("100.64.0.5"))
	if err != nil {
		t.Fatalf("server stack: %v", err)
	}
	t.Cleanup(srv.Close)
	enableTransportTCPForwarder(srv, transport)

	cli, cliEp, err := newRunStack(netip.MustParseAddr("192.0.2.2"))
	if err != nil {
		t.Fatalf("client stack: %v", err)
	}
	t.Cleanup(cli.Close)
	// v6 source for fd78:: dials — mirrors the child netns, which
	// binds runTunAddr6 to its TUN. (Production's daemon-side stack
	// gets no v6 address, exactly like srv above: promiscuous +
	// spoofing handle inbound v6 there.)
	pa6 := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(netip.MustParseAddr(runTunAddr6).AsSlice()).WithPrefix(),
	}
	if e := cli.AddProtocolAddress(1, pa6, stack.AddressProperties{}); e != nil {
		t.Fatalf("client v6 address: %v", e)
	}

	go pump(ctx, srvEp, cliEp)
	go pump(ctx, cliEp, srvEp)
	return cli
}

// forwarderDsts covers both address families the forwarder must
// serve: the v4 VIP range and the fd78:: v6 VIP range (#765).
var forwarderDsts = []struct {
	name string
	addr netip.Addr
}{
	{name: "ipv4", addr: netip.MustParseAddr("10.78.1.2")},
	{name: "ipv6 fd78 vip", addr: netip.MustParseAddr("fd78::1234")},
}

func dialThroughHarness(t *testing.T, cli *stack.Stack, dst netip.Addr) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proto := ipv4.ProtocolNumber
	if dst.Is6() {
		proto = ipv6.ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, cli, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(dst.AsSlice()),
		Port: 5432,
	}, proto)
}

// A transport dial failure must surface to the child as a refused
// connect (RST), not as an accepted connection that then hangs —
// getaddrinfo/Happy-Eyeballs address fallback depends on connect()
// failing (#765). Asserting on the error text and the elapsed time
// distinguishes a fast RST from a stranded SYN that only dies with
// the dial context's 10s deadline.
func TestRunStackTCPForwarderDialFailureRefusesConnect(t *testing.T) {
	for _, dst := range forwarderDsts {
		t.Run(dst.name, func(t *testing.T) {
			ft := &fakeTransport{dial: func(string, string) (net.Conn, error) {
				return nil, context.DeadlineExceeded
			}}
			cli := newForwarderHarness(t, ft)

			start := time.Now()
			c, err := dialThroughHarness(t, cli, dst.addr)
			elapsed := time.Since(start)
			if err == nil {
				_ = c.Close()
				t.Fatalf("connect succeeded despite transport dial failure; want refused")
			}
			if !strings.Contains(err.Error(), "refused") {
				t.Fatalf("connect error = %v; want connection refused", err)
			}
			if elapsed > 5*time.Second {
				t.Fatalf("refusal took %v; want well under the 10s dial deadline", elapsed)
			}
			if got := ft.dialedAddrs(); len(got) != 1 {
				t.Fatalf("transport dials = %v, want exactly one attempt", got)
			}
		})
	}
}

func TestRunStackTCPForwarderRelays(t *testing.T) {
	for _, dst := range forwarderDsts {
		t.Run(dst.name, func(t *testing.T) {
			var (
				mu   sync.Mutex
				peer net.Conn
			)
			ft := &fakeTransport{dial: func(string, string) (net.Conn, error) {
				a, b := net.Pipe()
				mu.Lock()
				peer = b
				mu.Unlock()
				return a, nil
			}}
			cli := newForwarderHarness(t, ft)

			c, err := dialThroughHarness(t, cli, dst.addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = c.Close() }()

			mu.Lock()
			up := peer
			mu.Unlock()
			if up == nil {
				t.Fatalf("transport.Dial never called")
			}
			defer func() { _ = up.Close() }()

			deadline := time.Now().Add(10 * time.Second)
			_ = c.SetDeadline(deadline)
			_ = up.SetDeadline(deadline)

			if _, err := c.Write([]byte("hello")); err != nil {
				t.Fatalf("client write: %v", err)
			}
			buf := make([]byte, 5)
			if _, err := readFull(up, buf); err != nil || string(buf) != "hello" {
				t.Fatalf("upstream read = %q, %v", buf, err)
			}
			if _, err := up.Write([]byte("world")); err != nil {
				t.Fatalf("upstream write: %v", err)
			}
			if _, err := readFull(c, buf); err != nil || string(buf) != "world" {
				t.Fatalf("client read = %q, %v", buf, err)
			}

			want := "tcp|" + net.JoinHostPort(dst.addr.String(), "5432")
			if got := ft.dialedAddrs(); len(got) != 1 || got[0] != want {
				t.Fatalf("dialed = %v, want [%s]", got, want)
			}
		})
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

type udpForwarderHarness struct {
	cli       *stack.Stack
	cancel    context.CancelFunc
	responses chan []byte
}

func newUDPForwarderHarness(t *testing.T, transport daemonTransport, idleTimeout time.Duration) *udpForwarderHarness {
	return newUDPForwarderHarnessWithLimit(t, transport, idleTimeout, runUDPFlowLimit)
}

func newUDPForwarderHarnessWithLimit(t *testing.T, transport daemonTransport, idleTimeout time.Duration, flowLimit int) *udpForwarderHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	daemonTun := os.NewFile(uintptr(fds[0]), "daemon-tun")
	clientTun := os.NewFile(uintptr(fds[1]), "client-tun")
	t.Cleanup(func() { _ = daemonTun.Close() })
	t.Cleanup(func() { _ = clientTun.Close() })

	srv, srvEp, err := newRunStack(netip.MustParseAddr("100.64.0.5"))
	if err != nil {
		t.Fatalf("server stack: %v", err)
	}
	t.Cleanup(srv.Close)
	enableTransportUDPForwarderWithLimit(ctx, srv, transport, idleTimeout, flowLimit)
	startTunBridge(daemonTun, srvEp)

	cliEp := channel.New(netstackQueueSize, uint32(runStackTunMTU), "")
	cli := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(cli.Close)
	if e := cli.CreateNIC(1, cliEp); e != nil {
		t.Fatalf("client CreateNIC: %v", e)
	}
	for _, addr := range []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr(runTunAddr6)} {
		proto := ipv4.ProtocolNumber
		if addr.Is6() {
			proto = ipv6.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
		if e := cli.AddProtocolAddress(1, pa, stack.AddressProperties{}); e != nil {
			t.Fatalf("client address %s: %v", addr, e)
		}
	}
	cli.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	cli.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	responses := make(chan []byte, 16)
	go func() {
		for {
			pkt := cliEp.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			_, _ = clientTun.Write(view.AsSlice())
		}
	}()
	go func() {
		buf := make([]byte, runStackTunMTU)
		for {
			n, err := clientTun.Read(buf)
			if err != nil {
				return
			}
			raw := slices.Clone(buf[:n])
			select {
			case responses <- slices.Clone(raw):
			default:
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			proto := header.IPv4ProtocolNumber
			if raw[0]>>4 == 6 {
				proto = header.IPv6ProtocolNumber
			}
			cliEp.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()
	return &udpForwarderHarness{cli: cli, cancel: cancel, responses: responses}
}

func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP echo: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP(buf[:n], addr)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr)
}

func dialUDPThroughHarness(t *testing.T, cli *stack.Stack, dst netip.Addr, port uint16) *gonet.UDPConn {
	t.Helper()
	proto := ipv4.ProtocolNumber
	if dst.Is6() {
		proto = ipv6.ProtocolNumber
	}
	c, err := gonet.DialUDP(cli, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.AsSlice()), Port: port}, proto)
	if err != nil {
		t.Fatalf("DialUDP %s: %v", dst, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func checksum16(parts ...[]byte) uint16 {
	var sum uint32
	for _, part := range parts {
		for len(part) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(part))
			part = part[2:]
		}
		if len(part) == 1 {
			sum += uint32(part[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func assertIPv6UDPResponse(t *testing.T, raw []byte, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) {
	t.Helper()
	if len(raw) != 48+len(payload) || raw[0]>>4 != 6 || raw[6] != byte(header.UDPProtocolNumber) {
		t.Fatalf("unexpected IPv6 UDP packet: len=%d", len(raw))
	}
	if got := netip.AddrFrom16([16]byte(raw[8:24])); got != src {
		t.Fatalf("source IP = %s, want %s", got, src)
	}
	if got := netip.AddrFrom16([16]byte(raw[24:40])); got != dst {
		t.Fatalf("destination IP = %s, want %s", got, dst)
	}
	udpPacket := raw[40:]
	if got := binary.BigEndian.Uint16(udpPacket[0:2]); got != srcPort {
		t.Fatalf("source port = %d, want %d", got, srcPort)
	}
	if got := binary.BigEndian.Uint16(udpPacket[2:4]); got != dstPort {
		t.Fatalf("destination port = %d, want %d", got, dstPort)
	}
	if got := binary.BigEndian.Uint16(udpPacket[6:8]); got == 0 {
		t.Fatal("IPv6 UDP checksum is zero")
	}
	if !slices.Equal(udpPacket[8:], payload) {
		t.Fatalf("payload = %q, want %q", udpPacket[8:], payload)
	}
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], raw[8:24])
	copy(pseudo[16:32], raw[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udpPacket)))
	pseudo[39] = byte(header.UDPProtocolNumber)
	if got := checksum16(pseudo, udpPacket); got != 0xffff {
		t.Fatalf("IPv6 UDP checksum folds to %#04x, want 0xffff", got)
	}
}

type closeNotifyConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestRunStackUDPForwarderDialFailureDoesNotRetainFlow(t *testing.T) {
	for _, dst := range []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("fd78::53")} {
		t.Run(dst.String(), func(t *testing.T) {
			ft := &fakeTransport{dial: func(string, string) (net.Conn, error) { return nil, context.DeadlineExceeded }}
			h := newUDPForwarderHarness(t, ft, time.Minute)
			c := dialUDPThroughHarness(t, h.cli, dst, 5353)
			if _, err := c.Write([]byte("fail")); err != nil {
				t.Fatalf("first write: %v", err)
			}
			deadline := time.Now().Add(500 * time.Millisecond)
			for len(ft.dialedAddrs()) < 1 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			_, portText, err := net.SplitHostPort(c.LocalAddr().String())
			if err != nil {
				t.Fatalf("local address: %v", err)
			}
			localPort, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatalf("local port: %v", err)
			}
			_ = c.Close()

			proto := ipv4.ProtocolNumber
			localIP := netip.MustParseAddr("192.0.2.2")
			if dst.Is6() {
				proto = ipv6.ProtocolNumber
				localIP = netip.MustParseAddr(runTunAddr6)
			}
			local := &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(localIP.AsSlice()), Port: uint16(localPort)}
			remote := &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.AsSlice()), Port: 5353}
			retry, terr := gonet.DialUDP(h.cli, local, remote, proto)
			if terr != nil {
				t.Fatalf("recreate same tuple: %v", terr)
			}
			defer func() { _ = retry.Close() }()
			if _, err := retry.Write([]byte("fresh request")); err != nil {
				t.Fatalf("fresh write: %v", err)
			}
			for len(ft.dialedAddrs()) < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			wantDial := "udp|" + net.JoinHostPort(dst.String(), "5353")
			want := []string{wantDial, wantDial}
			if got := ft.dialedAddrs(); !slices.Equal(got, want) {
				t.Fatalf("dialed = %v, want %v; failed request was retained as a black hole", got, want)
			}
		})
	}
}

func TestRunStackUDPForwarderBlockedDialDoesNotBlockIngress(t *testing.T) {
	block := make(chan struct{})
	started := make(chan string, 2)
	ft := &fakeTransport{dial: func(_ string, addr string) (net.Conn, error) {
		started <- addr
		if strings.HasSuffix(addr, ":5301") {
			<-block
		}
		return nil, context.DeadlineExceeded
	}}
	h := newUDPForwarderHarnessWithLimit(t, ft, time.Minute, 2)
	first := dialUDPThroughHarness(t, h.cli, netip.MustParseAddr("192.0.2.53"), 5301)
	second := dialUDPThroughHarness(t, h.cli, netip.MustParseAddr("192.0.2.54"), 5302)
	if _, err := first.Write([]byte("block")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first dial did not start")
	}
	if _, err := second.Write([]byte("must progress")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-started:
		if !strings.HasSuffix(got, ":5302") {
			t.Fatalf("second dial = %q", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("second UDP flow was blocked behind transport.Dial")
	}
	close(block)
}

func TestRunStackUDPForwarderFlowLimitReleasesAfterDialFailure(t *testing.T) {
	block := make(chan struct{})
	started := make(chan string, 2)
	ft := &fakeTransport{dial: func(_ string, addr string) (net.Conn, error) {
		started <- addr
		if strings.HasSuffix(addr, ":5301") {
			<-block
		}
		return nil, context.DeadlineExceeded
	}}
	h := newUDPForwarderHarnessWithLimit(t, ft, time.Minute, 1)
	first := dialUDPThroughHarness(t, h.cli, netip.MustParseAddr("192.0.2.53"), 5301)
	second := dialUDPThroughHarness(t, h.cli, netip.MustParseAddr("192.0.2.54"), 5302)
	_, _ = first.Write([]byte("occupy"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first dial did not start")
	}
	_, _ = second.Write([]byte("full"))
	select {
	case got := <-started:
		t.Fatalf("dial %q admitted above limit", got)
	case <-time.After(50 * time.Millisecond):
	}
	close(block)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	retry := time.NewTicker(time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-started:
			return
		case <-retry.C:
			_ = second.Close()
			second = dialUDPThroughHarness(t, h.cli, netip.MustParseAddr("192.0.2.54"), 5302)
			_, _ = second.Write([]byte("released"))
		case <-deadline.C:
			t.Fatal("slot not released after dial failure")
		}
	}
}

func TestRunUDPRelayBufferPoolNormalizesFullDatagramBuffer(t *testing.T) {
	first := getRunUDPRelayBuffer()
	if len(first) != runStackTunMTU || cap(first) != runStackTunMTU {
		t.Fatalf("buffer len/cap = %d/%d, want %d/%d", len(first), cap(first), runStackTunMTU, runStackTunMTU)
	}
	putRunUDPRelayBuffer(first[:1])
	second := getRunUDPRelayBuffer()
	defer putRunUDPRelayBuffer(second)
	if len(second) != runStackTunMTU || cap(second) != runStackTunMTU {
		t.Fatalf("buffer after shortened Put has len/cap = %d/%d, want %d/%d", len(second), cap(second), runStackTunMTU, runStackTunMTU)
	}
}

func TestUDPIdleRemainingHonorsActivityAtExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	const timeout = 50 * time.Millisecond
	last := now.Add(-timeout + time.Nanosecond).UnixNano()
	if got := udpIdleRemaining(last, now, timeout); got != time.Nanosecond {
		t.Fatalf("remaining = %v, want 1ns; timer expiry must re-check successful activity", got)
	}
}

func TestRunStackUDPForwarderSessionCleanup(t *testing.T) {
	echo := startUDPEcho(t)
	closed := make(chan chan struct{}, 2)
	ft := &fakeTransport{dial: func(network, _ string) (net.Conn, error) {
		c, err := net.DialUDP(network, nil, echo)
		if err != nil {
			return nil, err
		}
		notify := make(chan struct{})
		closed <- notify
		return &closeNotifyConn{Conn: c, closed: notify}, nil
	}}
	h := newUDPForwarderHarness(t, ft, time.Minute)
	for _, dst := range []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("fd78::53")} {
		c := dialUDPThroughHarness(t, h.cli, dst, 5353)
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("establish")); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
		buf := make([]byte, 32)
		if _, err := c.Read(buf); err != nil {
			t.Fatalf("read %s: %v", dst, err)
		}
	}
	notifications := []chan struct{}{<-closed, <-closed}
	h.cancel()
	for i, notify := range notifications {
		select {
		case <-notify:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("flow %d remained open after session cancellation", i)
		}
	}
}

func TestRunStackUDPForwarderActivityRefreshesIdleTimeout(t *testing.T) {
	for _, direction := range []string{"child-to-upstream", "upstream-to-child"} {
		t.Run(direction, func(t *testing.T) {
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = server.Close() }()
			peerCh := make(chan *net.UDPAddr, 1)
			go func() {
				buf := make([]byte, 32)
				for {
					_, peer, err := server.ReadFromUDP(buf)
					if err != nil {
						return
					}
					select {
					case peerCh <- peer:
					default:
					}
				}
			}()
			closed := make(chan struct{})
			ft := &fakeTransport{dial: func(network, _ string) (net.Conn, error) {
				c, err := net.DialUDP(network, nil, server.LocalAddr().(*net.UDPAddr))
				if err != nil {
					return nil, err
				}
				return &closeNotifyConn{Conn: c, closed: closed}, nil
			}}
			h := newUDPForwarderHarness(t, ft, 60*time.Millisecond)
			c := dialUDPThroughHarness(t, h.cli, netip.MustParseAddr("fd78::53"), 5353)
			_ = c.SetDeadline(time.Now().Add(time.Second))
			if _, err := c.Write([]byte("establish")); err != nil {
				t.Fatalf("establish: %v", err)
			}
			peer := <-peerCh
			for i := 0; i < 4; i++ {
				time.Sleep(35 * time.Millisecond)
				if direction == "child-to-upstream" {
					if _, err := c.Write([]byte("active")); err != nil {
						t.Fatalf("child activity: %v", err)
					}
				} else {
					if _, err := server.WriteToUDP([]byte("active"), peer); err != nil {
						t.Fatalf("upstream activity: %v", err)
					}
					if _, err := c.Read(make([]byte, 32)); err != nil {
						t.Fatalf("client read activity: %v", err)
					}
				}
				select {
				case <-closed:
					t.Fatal("flow closed despite successful one-way activity")
				default:
				}
			}
			select {
			case <-closed:
			case <-time.After(300 * time.Millisecond):
				t.Fatal("flow did not close after activity stopped")
			}
		})
	}
}

func TestRunStackUDPForwarderIdleCleanup(t *testing.T) {
	echo := startUDPEcho(t)
	closeNotifications := make(chan chan struct{}, 2)
	ft := &fakeTransport{dial: func(network, _ string) (net.Conn, error) {
		c, err := net.DialUDP(network, nil, echo)
		if err != nil {
			return nil, err
		}
		closed := make(chan struct{})
		closeNotifications <- closed
		return &closeNotifyConn{Conn: c, closed: closed}, nil
	}}
	h := newUDPForwarderHarness(t, ft, 80*time.Millisecond)
	dst := netip.MustParseAddr("fd78::53")
	c := dialUDPThroughHarness(t, h.cli, dst, 5353)
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, portText, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		t.Fatalf("local address: %v", err)
	}
	localPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("local port: %v", err)
	}
	if _, err := c.Write([]byte("establish")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 32)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	firstClosed := <-closeNotifications
	select {
	case <-firstClosed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("idle flow did not close upstream connection")
	}
	_ = c.Close()

	local := &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(netip.MustParseAddr(runTunAddr6).AsSlice()), Port: uint16(localPort)}
	remote := &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.AsSlice()), Port: 5353}
	retry, terr := gonet.DialUDP(h.cli, local, remote, ipv6.ProtocolNumber)
	if terr != nil {
		t.Fatalf("recreate expired tuple: %v", terr)
	}
	defer func() { _ = retry.Close() }()
	if _, err := retry.Write([]byte("fresh")); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	select {
	case <-closeNotifications:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expired endpoint retained tuple; no fresh transport dial")
	}
	if got := len(ft.dialedAddrs()); got != 2 {
		t.Fatalf("transport dials = %d, want 2 after recreating expired tuple", got)
	}
}

func TestRunStackUDPForwarderIsolatesConcurrentFlows(t *testing.T) {
	var (
		serversMu sync.Mutex
		servers   []*net.UDPConn
	)
	t.Cleanup(func() {
		serversMu.Lock()
		defer serversMu.Unlock()
		for _, server := range servers {
			_ = server.Close()
		}
	})
	ft := &fakeTransport{dial: func(network, addr string) (net.Conn, error) {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		serversMu.Lock()
		servers = append(servers, server)
		serversMu.Unlock()
		go func() {
			buf := make([]byte, 256)
			n, peer, err := server.ReadFromUDP(buf)
			if err == nil {
				_, _ = server.WriteToUDP(append([]byte(addr+"|"), buf[:n]...), peer)
			}
		}()
		return net.DialUDP(network, nil, server.LocalAddr().(*net.UDPAddr))
	}}
	h := newUDPForwarderHarness(t, ft, time.Minute)
	flows := []struct {
		dst  netip.Addr
		port uint16
	}{
		{netip.MustParseAddr("192.0.2.53"), 5301},
		{netip.MustParseAddr("192.0.2.54"), 5302},
		{netip.MustParseAddr("fd78::53"), 5303},
		{netip.MustParseAddr("2001:db8:781::54"), 5304},
	}
	start := make(chan struct{})
	errs := make(chan error, len(flows))
	conns := make([]*gonet.UDPConn, len(flows))
	for i, flow := range flows {
		conns[i] = dialUDPThroughHarness(t, h.cli, flow.dst, flow.port)
	}
	for i, flow := range flows {
		go func(i int, flow struct {
			dst  netip.Addr
			port uint16
		}) {
			c := conns[i]
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			<-start
			payload := []byte(strconv.Itoa(i))
			if _, err := c.Write(payload); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, 256)
			n, err := c.Read(buf)
			want := net.JoinHostPort(flow.dst.String(), strconv.Itoa(int(flow.port))) + "|" + string(payload)
			if err != nil || string(buf[:n]) != want {
				errs <- fmt.Errorf("flow %s read %q, %w; want %q", flow.dst, buf[:n], err, want)
				return
			}
			errs <- nil
		}(i, flow)
	}
	close(start)
	for range flows {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	got := ft.dialedAddrs()
	slices.Sort(got)
	want := make([]string, 0, len(flows))
	for _, flow := range flows {
		want = append(want, "udp|"+net.JoinHostPort(flow.dst.String(), strconv.Itoa(int(flow.port))))
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("dialed = %v, want %v", got, want)
	}
}

func TestRunStackUDPForwarderZeroLengthDatagram(t *testing.T) {
	for _, dst := range []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("fd78::53")} {
		t.Run(dst.String(), func(t *testing.T) {
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = echo.Close() }()
			observed := make(chan int, 1)
			go func() {
				buf := make([]byte, 1)
				n, addr, err := echo.ReadFromUDP(buf)
				if err == nil {
					observed <- n
					_, _ = echo.WriteToUDP(buf[:n], addr)
				}
			}()
			ft := &fakeTransport{dial: func(network, _ string) (net.Conn, error) {
				return net.DialUDP(network, nil, echo.LocalAddr().(*net.UDPAddr))
			}}
			h := newUDPForwarderHarness(t, ft, time.Minute)
			c := dialUDPThroughHarness(t, h.cli, dst, 5353)
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if n, err := c.Write(nil); err != nil || n != 0 {
				t.Fatalf("zero write = %d, %v", n, err)
			}
			select {
			case n := <-observed:
				if n != 0 {
					t.Fatalf("upstream observed length %d, want 0", n)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("upstream did not observe zero-length datagram")
			}
			buf := make([]byte, 1)
			if n, err := c.Read(buf); err != nil || n != 0 {
				t.Fatalf("zero read = %d, %v", n, err)
			}
		})
	}
}

func TestRunStackUDPForwarderIPv4RoundTrip(t *testing.T) {
	echo := startUDPEcho(t)
	ft := &fakeTransport{dial: func(network, _ string) (net.Conn, error) { return net.DialUDP(network, nil, echo) }}
	h := newUDPForwarderHarness(t, ft, time.Minute)
	dst := netip.MustParseAddr("192.0.2.53")
	const dstPort = 5353
	payload := []byte("ipv4 survives")
	c := dialUDPThroughHarness(t, h.cli, dst, dstPort)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || !slices.Equal(buf[:n], payload) {
		t.Fatalf("read = %q, %v; want %q", buf[:n], err, payload)
	}
	raw := <-h.responses
	if len(raw) != 28+len(payload) || raw[0]>>4 != 4 {
		t.Fatalf("unexpected IPv4 packet length/version: len=%d", len(raw))
	}
	ihl := int(raw[0]&0xf) * 4
	if got := netip.AddrFrom4([4]byte(raw[12:16])); got != dst {
		t.Fatalf("source IP = %s, want %s", got, dst)
	}
	if got := netip.AddrFrom4([4]byte(raw[16:20])); got != netip.MustParseAddr("192.0.2.2") {
		t.Fatalf("destination IP = %s", got)
	}
	if got := binary.BigEndian.Uint16(raw[ihl : ihl+2]); got != dstPort {
		t.Fatalf("source port = %d, want %d", got, dstPort)
	}
	if !slices.Equal(raw[ihl+8:], payload) {
		t.Fatalf("raw payload = %q, want %q", raw[ihl+8:], payload)
	}
	want := []string{"udp|192.0.2.53:5353"}
	if got := ft.dialedAddrs(); !slices.Equal(got, want) {
		t.Fatalf("dialed = %v, want %v", got, want)
	}
}

func TestRunStackUDPForwarderIPv6RoundTrip(t *testing.T) {
	echo := startUDPEcho(t)
	ft := &fakeTransport{dial: func(network, _ string) (net.Conn, error) { return net.DialUDP(network, nil, echo) }}
	h := newUDPForwarderHarness(t, ft, time.Minute)
	for _, dst := range []netip.Addr{netip.MustParseAddr("fd78::1234"), netip.MustParseAddr("2001:db8:781::53")} {
		t.Run(dst.String(), func(t *testing.T) {
			const dstPort = 5353
			payload := []byte("odd-length")
			c := dialUDPThroughHarness(t, h.cli, dst, dstPort)
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 64)
			n, err := c.Read(buf)
			if err != nil || !slices.Equal(buf[:n], payload) {
				t.Fatalf("read = %q, %v; want %q", buf[:n], err, payload)
			}
			var raw []byte
			select {
			case raw = <-h.responses:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for raw response")
			}
			host, portText, err := net.SplitHostPort(c.LocalAddr().String())
			if err != nil || host != runTunAddr6 {
				t.Fatalf("client local address = %v, split error %v", c.LocalAddr(), err)
			}
			localPort, err := net.LookupPort("udp", portText)
			if err != nil {
				t.Fatalf("client local port: %v", err)
			}
			assertIPv6UDPResponse(t, raw, dst, netip.MustParseAddr(runTunAddr6), dstPort, uint16(localPort), payload)
		})
	}
	want := []string{"udp|[fd78::1234]:5353", "udp|[2001:db8:781::53]:5353"}
	if got := ft.dialedAddrs(); !slices.Equal(got, want) {
		t.Fatalf("dialed = %v, want %v", got, want)
	}
}
