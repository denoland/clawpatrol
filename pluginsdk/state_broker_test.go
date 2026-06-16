package pluginsdk

import (
	"context"
	"sync"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/extplugin"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// brokerTestHostState is a map-backed pb.HostStateServer standing in for
// the gateway in the round-trip test.
type brokerTestHostState struct {
	pb.UnimplementedHostStateServer
	mu sync.Mutex
	m  map[string][]byte
}

func (h *brokerTestHostState) Get(_ context.Context, r *pb.StateGetRequest) (*pb.StateGetResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.m[r.GetKey()]
	return &pb.StateGetResponse{Value: v, Found: ok}, nil
}

func (h *brokerTestHostState) Put(_ context.Context, r *pb.StatePutRequest) (*pb.StatePutResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.m[r.GetKey()] = r.GetValue()
	return &pb.StatePutResponse{}, nil
}

// brokerTestPlugin wires both sides exactly as the real code does: the
// server (plugin) side captures the broker for the SDK's State()
// accessor; the client (gateway) side serves HostState on the reserved
// broker id.
type brokerTestPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	host *brokerTestHostState
}

func (p *brokerTestPlugin) GRPCServer(broker *goplugin.GRPCBroker, _ *grpc.Server) error {
	setHostBroker(broker)
	return nil
}

func (p *brokerTestPlugin) GRPCClient(_ context.Context, broker *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	go broker.AcceptAndServe(extplugin.HostServicesBrokerID, func(opts []grpc.ServerOption) *grpc.Server {
		srv := grpc.NewServer(opts...)
		pb.RegisterHostStateServer(srv, p.host)
		return srv
	})
	return c, nil
}

// TestStateBrokerRoundTrip exercises the full plugin->gateway path over a
// real go-plugin broker: the SDK's State() dials the reserved stream id
// the gateway serves HostState on.
func TestStateBrokerRoundTrip(t *testing.T) {
	// Reset the package-level state client so the dial runs fresh. This
	// reassigns globals without synchronization, which is safe ONLY
	// because this is the single test that exercises State(): it runs
	// before any broker goroutine of its own starts, and no other test in
	// the package touches these globals concurrently.
	hostStateOnce = sync.Once{}
	hostStateCli = nil
	hostStateErr = nil
	setHostBroker(nil)

	host := &brokerTestHostState{m: map[string][]byte{}}
	client, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{
		"x": &brokerTestPlugin{host: host},
	})
	defer func() { _ = client.Close() }()

	// Dispense triggers the client-side GRPCClient, which starts the
	// gateway's AcceptAndServe.
	if _, err := client.Dispense("x"); err != nil {
		t.Fatalf("dispense: %v", err)
	}

	ctx := context.Background()
	if err := State().Put(ctx, "host_key", []byte("abc")); err != nil {
		t.Fatalf("put over broker: %v", err)
	}
	v, found, err := State().Get(ctx, "host_key")
	if err != nil || !found || string(v) != "abc" {
		t.Fatalf("get over broker = %q found=%v err=%v, want abc", v, found, err)
	}
}
