package extplugin

import (
	"context"
	"testing"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ctrlTestPlugin wires both sides over a real go-plugin broker, exactly as
// the gateway/plugin do: the server (plugin) side captures the broker so
// the plugin can dial the capability bundle; the client (gateway) side
// serves HostControl on the reserved broker id, backed by a session
// registry.
type ctrlTestPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	broker   *goplugin.GRPCBroker
	sessions *sessionRegistry
}

func (p *ctrlTestPlugin) GRPCServer(broker *goplugin.GRPCBroker, _ *grpc.Server) error {
	p.broker = broker
	return nil
}

func (p *ctrlTestPlugin) GRPCClient(_ context.Context, broker *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	go broker.AcceptAndServe(HostServicesBrokerID, func(opts []grpc.ServerOption) *grpc.Server {
		s := grpc.NewServer(opts...)
		pb.RegisterHostControlServer(s, newHostControl(p.sessions))
		return s
	})
	return c, nil
}

// TestHostControlEvaluateRoundTrip is the capability-bundle spike: a plugin
// runs a rule evaluation by calling a plain gRPC method over the broker —
// no EvaluateAction frame, no call_id, no inflight correlation map. The
// gateway routes the call to the connection's evaluator via a session
// token, and rejects a token it never issued.
func TestHostControlEvaluateRoundTrip(t *testing.T) {
	sessions := newSessionRegistry()
	// What HandleConn would register when a connection starts: the same
	// rule + approve work pumpConn's EvaluateAction branch does today.
	var gotFacet string
	var gotAction []byte
	sessions.register("tok-1", func(_ context.Context, facet string, action []byte, _ string) (string, string, string, error) {
		gotFacet = facet
		gotAction = action
		if facet == "http" {
			return "allow", "matched", "rule-1", nil
		}
		return "deny", "no rule", "", nil
	})

	p := &ctrlTestPlugin{sessions: sessions}
	client, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{"x": p})
	defer func() { _ = client.Close() }()
	if _, err := client.Dispense("x"); err != nil {
		t.Fatalf("dispense: %v", err)
	}

	conn, err := p.broker.Dial(HostServicesBrokerID)
	if err != nil {
		t.Fatalf("dial broker: %v", err)
	}
	ctrl := pb.NewHostControlClient(conn)

	// The whole client side: one call, gRPC correlates the reply.
	v, err := ctrl.Evaluate(context.Background(), &pb.EvaluateRequest{
		SessionToken: "tok-1",
		FacetName:    "http",
		ActionJson:   []byte(`{"method":"GET"}`),
		Summary:      "GET /",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if v.Action != "allow" || v.Rule != "rule-1" {
		t.Fatalf("verdict = %+v, want allow/rule-1", v)
	}
	if gotFacet != "http" || string(gotAction) != `{"method":"GET"}` {
		t.Fatalf("gateway saw facet=%q action=%q", gotFacet, gotAction)
	}

	// A token the gateway never issued is rejected — a plugin cannot
	// evaluate against a connection context it does not own.
	_, err = ctrl.Evaluate(context.Background(), &pb.EvaluateRequest{SessionToken: "forged", FacetName: "http"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("forged token err = %v, want NotFound", err)
	}

	// Once the connection ends and its token is removed, further calls on
	// it are rejected — no dangling evaluation context.
	sessions.remove("tok-1")
	_, err = ctrl.Evaluate(context.Background(), &pb.EvaluateRequest{SessionToken: "tok-1", FacetName: "http"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("removed token err = %v, want NotFound", err)
	}
}
