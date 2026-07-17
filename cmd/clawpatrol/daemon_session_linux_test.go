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
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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
