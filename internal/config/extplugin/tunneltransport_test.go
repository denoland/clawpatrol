package extplugin

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// echoParent is a fake parent runtime.Tunnel: every Dial returns a conn
// that echoes whatever is written to it, and records what it was asked to
// dial. Stands in for a real parent tunnel (a SOCKS plugin, ssh_port_forward)
// on the via route.
type echoParent struct{ network, addr chan string }

func (e echoParent) Dial(_ context.Context, network, addr string) (net.Conn, error) {
	select {
	case e.network <- network:
	default:
	}
	select {
	case e.addr <- addr:
	default:
	}
	return echoConn(), nil
}

func (echoParent) Close() error { return nil }

func echoConn() net.Conn {
	c1, c2 := net.Pipe()
	go func() { _, _ = io.Copy(c2, c2) }() // echo bytes written to c1
	return c1
}

// transportBrokerPlugin wires a go-plugin broker so the gateway serves
// HostTunnel and the plugin side can call DialUpstream — the real path a
// tunnel plugin's req.DialUpstream takes, minus the SDK wrapper.
type transportBrokerPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	reg        *transportRouteRegistry
	directDial func(network, addr string) (net.Conn, error)
	brokerCh   chan *goplugin.GRPCBroker
}

func (p *transportBrokerPlugin) GRPCServer(broker *goplugin.GRPCBroker, _ *grpc.Server) error {
	p.brokerCh <- broker
	return nil
}

func (p *transportBrokerPlugin) GRPCClient(_ context.Context, broker *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	go broker.AcceptAndServe(HostServicesBrokerID, func(opts []grpc.ServerOption) *grpc.Server {
		s := grpc.NewServer(opts...)
		pb.RegisterHostTunnelServer(s, &hostTunnel{reg: p.reg, directDial: p.directDial})
		return s
	})
	return c, nil
}

func dialUpstream(t *testing.T, broker *goplugin.GRPCBroker, token, network, addr string) (pb.HostTunnel_DialUpstreamClient, error) {
	t.Helper()
	conn, err := broker.Dial(HostServicesBrokerID)
	if err != nil {
		t.Fatalf("dial host services: %v", err)
	}
	stream, err := pb.NewHostTunnelClient(conn).DialUpstream(context.Background())
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	err = stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Init{Init: &pb.DialInit{
		TunnelHandle: token, Network: network, Addr: addr,
	}}})
	return stream, err
}

// TestDialUpstreamRoutes exercises the brokered transport dial over a real
// broker: a chained tunnel's dial is routed through its parent, a direct
// tunnel's dial goes through the gateway's injected dialer, and an unknown
// token is refused.
func TestDialUpstreamRoutes(t *testing.T) {
	parent := echoParent{network: make(chan string, 1), addr: make(chan string, 1)}
	reg := newTransportRouteRegistry()
	viaToken := reg.add(parent) // chained: route through the parent
	directToken := reg.add(nil) // direct: route through the gateway dialer

	// directDial stands in for the gateway's own dialer: an echo target.
	var directNet, directAddr string
	directDial := func(network, addr string) (net.Conn, error) {
		directNet, directAddr = network, addr
		return echoConn(), nil
	}

	brokerCh := make(chan *goplugin.GRPCBroker, 1)
	client, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{
		"x": &transportBrokerPlugin{reg: reg, directDial: directDial, brokerCh: brokerCh},
	})
	defer func() { _ = client.Close() }()
	if _, err := client.Dispense("x"); err != nil {
		t.Fatalf("dispense: %v", err)
	}
	broker := <-brokerCh

	// Chained: dial routes through the parent (which echoes), and the parent
	// sees the child's udp/endpoint request.
	viaStream, err := dialUpstream(t, broker, viaToken, "udp", "wg.example:51820")
	if err != nil {
		t.Fatalf("via send init: %v", err)
	}
	if got := echoRoundTrip(t, viaStream, "handshake"); got != "handshake" {
		t.Fatalf("via echo = %q", got)
	}
	if n := <-parent.network; n != "udp" {
		t.Fatalf("parent dialed network %q, want udp", n)
	}
	if a := <-parent.addr; a != "wg.example:51820" {
		t.Fatalf("parent dialed addr %q", a)
	}

	// Direct: dial goes through the gateway's injected dialer (echo target).
	directStream, err := dialUpstream(t, broker, directToken, "tcp", "bastion:22")
	if err != nil {
		t.Fatalf("direct send init: %v", err)
	}
	if got := echoRoundTrip(t, directStream, "ping"); got != "ping" {
		t.Fatalf("direct echo = %q", got)
	}
	if directNet != "tcp" || directAddr != "bastion:22" {
		t.Fatalf("direct dialer got %q/%q, want tcp/bastion:22", directNet, directAddr)
	}

	// Half-close: when the plugin sends a DialClose, the bridge must tear
	// down and return — not leak a goroutine parked in conn.Read on the
	// still-open echo target.
	hc, err := dialUpstream(t, broker, directToken, "tcp", "bastion:22")
	if err != nil {
		t.Fatalf("half-close send init: %v", err)
	}
	if err := hc.Send(&pb.DialMessage{Kind: &pb.DialMessage_Close{Close: &pb.DialClose{}}}); err != nil {
		t.Fatalf("send close: %v", err)
	}
	recvErr := make(chan error, 1)
	go func() { _, e := hc.Recv(); recvErr <- e }()
	select {
	case <-recvErr: // handler returned, stream closed — the bridge tore down
	case <-time.After(3 * time.Second):
		t.Fatal("DialUpstream did not return after DialClose (bridge leak)")
	}

	// Unknown token must be refused.
	bad, _ := dialUpstream(t, broker, "not-a-real-token", "tcp", "x:1")
	if _, err := bad.Recv(); err == nil {
		t.Fatal("DialUpstream with unknown token should fail")
	}
}

func echoRoundTrip(t *testing.T, stream pb.HostTunnel_DialUpstreamClient, payload string) string {
	t.Helper()
	if err := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Data{
		Data: &pb.DialData{Payload: []byte(payload)},
	}}); err != nil {
		t.Fatalf("send data: %v", err)
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if d := msg.GetData(); d != nil {
			return string(d.GetPayload())
		}
	}
}

// TestFramedDatagramConn round-trips length-prefixed datagrams across
// arbitrary chunk boundaries — the gateway-side adapter for direct udp.
func TestFramedDatagramConn(t *testing.T) {
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(b, b) }() // echo the underlying "udp" conn
	f := newFramedDatagramConn(a)
	defer func() { _ = f.Close() }()
	_ = f.SetDeadline(time.Now().Add(2 * time.Second))

	// Two framed datagrams written in one Write must arrive as two packets,
	// echoed back and re-framed for the reader.
	want := []byte("alpha")
	frame := append([]byte{0, byte(len(want))}, want...)
	go func() { _, _ = f.Write(append(frame, frame...)) }()

	for i := 0; i < 2; i++ {
		got, err := readFrame(f)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if string(got) != "alpha" {
			t.Fatalf("frame %d = %q", i, got)
		}
	}
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, int(hdr[0])<<8|int(hdr[1]))
	_, err := io.ReadFull(r, buf)
	return buf, err
}

var _ runtime.Tunnel = echoParent{}
