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
// that echoes whatever is written to it. Stands in for a real parent
// tunnel (a SOCKS plugin, ssh_port_forward, ...) in the via round-trip.
type echoParent struct{ network, addr chan string }

func (e echoParent) Dial(_ context.Context, network, addr string) (net.Conn, error) {
	// Record what the gateway asked the parent to dial (so the test can
	// assert the child's "udp"/endpoint request reached the parent).
	select {
	case e.network <- network:
	default:
	}
	select {
	case e.addr <- addr:
	default:
	}
	c1, c2 := net.Pipe()
	go func() { _, _ = io.Copy(c2, c2) }() // echo bytes written to c1
	return c1, nil
}

func (echoParent) Close() error { return nil }

// viaBrokerPlugin wires a go-plugin broker so the gateway serves
// HostTunnel and the plugin side can call DialVia — the real path
// req.Via.Dial takes, minus the SDK wrapper.
type viaBrokerPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	reg      *viaRegistry
	brokerCh chan *goplugin.GRPCBroker
}

func (p *viaBrokerPlugin) GRPCServer(broker *goplugin.GRPCBroker, _ *grpc.Server) error {
	p.brokerCh <- broker // plugin side captures the broker to dial host services
	return nil
}

func (p *viaBrokerPlugin) GRPCClient(_ context.Context, broker *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	go broker.AcceptAndServe(HostServicesBrokerID, func(opts []grpc.ServerOption) *grpc.Server {
		s := grpc.NewServer(opts...)
		pb.RegisterHostTunnelServer(s, &hostTunnel{reg: p.reg})
		return s
	})
	return c, nil
}

// TestDialViaRoundTrip exercises the full plugin-tunnel `via` path over a
// real broker: the gateway registers a parent tunnel under a via token,
// serves HostTunnel, and a chained plugin dials THROUGH the parent by
// echoing the token to DialVia. Bytes must round-trip and the parent must
// see the child's requested network/addr.
func TestDialViaRoundTrip(t *testing.T) {
	parent := echoParent{network: make(chan string, 1), addr: make(chan string, 1)}
	reg := newViaRegistry()
	token := reg.add(parent)

	brokerCh := make(chan *goplugin.GRPCBroker, 1)
	client, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{
		"x": &viaBrokerPlugin{reg: reg, brokerCh: brokerCh},
	})
	defer func() { _ = client.Close() }()
	if _, err := client.Dispense("x"); err != nil {
		t.Fatalf("dispense: %v", err)
	}

	broker := <-brokerCh
	conn, err := broker.Dial(HostServicesBrokerID)
	if err != nil {
		t.Fatalf("dial host services: %v", err)
	}
	cli := pb.NewHostTunnelClient(conn)
	stream, err := cli.DialVia(context.Background())
	if err != nil {
		t.Fatalf("DialVia: %v", err)
	}
	// The child names its parent (the token) and the transport it wants —
	// here a udp conduit to a WireGuard endpoint.
	if err := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Init{Init: &pb.DialInit{
		TunnelHandle: token, Network: "udp", Addr: "wg.example:51820",
	}}}); err != nil {
		t.Fatalf("send init: %v", err)
	}
	if err := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Data{
		Data: &pb.DialData{Payload: []byte("handshake")},
	}}); err != nil {
		t.Fatalf("send data: %v", err)
	}

	got := recvData(t, stream)
	if string(got) != "handshake" {
		t.Fatalf("echoed payload = %q, want %q", got, "handshake")
	}

	// The gateway must have asked the PARENT to dial what the child named.
	select {
	case n := <-parent.network:
		if n != "udp" {
			t.Fatalf("parent dialed network %q, want udp", n)
		}
	case <-time.After(time.Second):
		t.Fatal("parent.Dial was never called")
	}
	if a := <-parent.addr; a != "wg.example:51820" {
		t.Fatalf("parent dialed addr %q, want wg.example:51820", a)
	}

	// An unknown via token must be refused (capability check).
	bad, _ := cli.DialVia(context.Background())
	_ = bad.Send(&pb.DialMessage{Kind: &pb.DialMessage_Init{Init: &pb.DialInit{
		TunnelHandle: "not-a-real-token", Network: "tcp", Addr: "x:1",
	}}})
	if _, err := bad.Recv(); err == nil {
		t.Fatal("DialVia with unknown token should fail")
	}
}

func recvData(t *testing.T, stream pb.HostTunnel_DialViaClient) []byte {
	t.Helper()
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		switch k := msg.GetKind().(type) {
		case *pb.DialMessage_Data:
			return k.Data.GetPayload()
		case *pb.DialMessage_Close:
			t.Fatal("got Close before Data")
		}
	}
}

var _ runtime.Tunnel = echoParent{}
