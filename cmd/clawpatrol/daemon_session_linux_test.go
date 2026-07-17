//go:build linux

package main

// Tests for the per-session gVisor TCP forwarder. A second gVisor
// stack stands in for the child's netns: the two channel endpoints
// are cross-pumped, so a gonet dial on the client stack behaves like
// the child's connect() through the TUN.

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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

	go pump(ctx, srvEp, cliEp)
	go pump(ctx, cliEp, srvEp)
	return cli
}

func dialThroughHarness(t *testing.T, cli *stack.Stack) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, cli, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(netip.MustParseAddr("10.78.1.2").AsSlice()),
		Port: 5432,
	}, ipv4.ProtocolNumber)
}

// A transport dial failure must surface to the child as a refused
// connect (RST), not as an accepted connection that then hangs —
// getaddrinfo/Happy-Eyeballs address fallback depends on connect()
// failing (#765).
func TestRunStackTCPForwarderDialFailureRefusesConnect(t *testing.T) {
	ft := &fakeTransport{dial: func(_, _ string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}}
	cli := newForwarderHarness(t, ft)

	c, err := dialThroughHarness(t, cli)
	if err == nil {
		_ = c.Close()
		t.Fatalf("connect succeeded despite transport dial failure; want refused")
	}
}

func TestRunStackTCPForwarderRelays(t *testing.T) {
	var (
		mu   sync.Mutex
		peer net.Conn
	)
	ft := &fakeTransport{dial: func(_, _ string) (net.Conn, error) {
		a, b := net.Pipe()
		mu.Lock()
		peer = b
		mu.Unlock()
		return a, nil
	}}
	cli := newForwarderHarness(t, ft)

	c, err := dialThroughHarness(t, cli)
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

	want := "tcp|10.78.1.2:5432"
	if got := ft.dialedAddrs(); len(got) != 1 || got[0] != want {
		t.Fatalf("dialed = %v, want [%s]", got, want)
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
