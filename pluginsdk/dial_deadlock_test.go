package pluginsdk

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestDialEarlyReturnDoesNotDeadlock pins the teardown ordering of the
// tunnel Dial handler. When the plugin's Dial callback returns before
// the gateway closes the conn (an upstream dial refused at the SOCKS
// layer, a validation failure, ...), the SDK must announce the Close on
// the Tunnel.Dial stream BEFORE waiting for the gateway to tear the
// stream down. The opposite order parks both sides in stream.Recv
// forever: the SDK waits for a message the gateway only sends after
// seeing our Close, and the gateway (dialConn.Read) waits for bytes
// that never come. The HandleConn path documents the same ordering
// requirement at its close announcement.
func TestDialEarlyReturnDoesNotDeadlock(t *testing.T) {
	// A tunnel whose Dial callback returns immediately without closing
	// the conn: the gateway-side conn stays open and idle.
	p := &Plugin{
		Name:    "earlyreturn",
		Version: "0.1.0",
		Tunnels: []TunnelDef{{
			TypeName: "early_return_tunnel",
			Dial: func(ctx context.Context, _ TunnelDialRequest, _ net.Conn) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				return errors.New("socks: connect: connection refused")
			},
		}},
	}
	srv := newServer(p)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g := grpc.NewServer()
	pb.RegisterTunnelServer(g, srv)
	go func() { _ = g.Serve(lis) }()
	defer g.Stop()

	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial sdk server: %v", err)
	}
	defer func() { _ = cc.Close() }()

	ctx := context.Background()
	tcli := pb.NewTunnelClient(cc)
	open, err := tcli.OpenTunnel(ctx, &pb.OpenTunnelRequest{
		TunnelTypeName: "early_return_tunnel",
		TunnelInstance: "demo",
	})
	if err != nil {
		t.Fatalf("open tunnel: %v", err)
	}

	ds, err := tcli.Dial(ctx)
	if err != nil {
		t.Fatalf("dial tunnel stream: %v", err)
	}
	if err := ds.Send(&pb.DialMessage{Kind: &pb.DialMessage_Init{Init: &pb.DialInit{
		TunnelHandle: open.GetHandle(),
		Network:      "tcp",
		Addr:         "10.0.0.5:8080",
	}}}); err != nil {
		t.Fatalf("send init: %v", err)
	}

	// The gateway side: it sits in dialConn.Read (stream.Recv) waiting
	// for the tunnel to produce bytes. The plugin's Dial already
	// returned, so the only thing that can arrive is the SDK's Close.
	// Once it does, tear the stream down the way dialConn.Close does
	// when the transport sees the EOF, and expect the handler to
	// return.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			msg, rerr := ds.Recv()
			if rerr != nil {
				return // handler returned; stream ended
			}
			if c := msg.GetClose(); c != nil {
				if c.Reason == "" {
					t.Errorf("close reason = %q, want the dial error", c.Reason)
				}
				_ = ds.CloseSend()
			}
		}
	}()
	select {
	case <-done:
		// The SDK sent its Close before waiting on the recv goroutine,
		// and returned once the gateway tore the stream down.
	case <-time.After(5 * time.Second):
		t.Fatal("Tunnel.Dial deadlocked: no Close frame after the Dial callback returned early")
	}
}
