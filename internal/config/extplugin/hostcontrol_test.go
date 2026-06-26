package extplugin

import (
	"context"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ctrlTestPlugin wires both sides over a real go-plugin broker, exactly as
// the gateway/plugin do: the server (plugin) side captures the broker so
// the plugin can dial the host services; the client (gateway) side
// serves HostControl on the reserved broker id behind the session
// interceptor, backed by a per-plugin session registry.
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
		opts = append(opts, grpc.ChainUnaryInterceptor(sessionUnaryInterceptor(p.sessions)))
		s := grpc.NewServer(opts...)
		pb.RegisterHostControlServer(s, hostControl{})
		return s
	})
	return c, nil
}

func dialHostControl(t *testing.T, p *ctrlTestPlugin) pb.HostControlClient {
	t.Helper()
	conn, err := p.broker.Dial(HostServicesBrokerID)
	if err != nil {
		t.Fatalf("dial broker: %v", err)
	}
	return pb.NewHostControlClient(conn)
}

// withSession returns a ctx carrying the session token as request metadata,
// the way the SDK client interceptor will.
func withSession(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), SessionMetadataKey, token)
}

// TestHostControlEvaluateRoundTrip: a plugin runs a rule evaluation by
// calling a plain gRPC method over the broker — no EvaluateAction frame, no
// call_id, no inflight correlation map. The gateway routes the call to the
// connection's session via the metadata token, resolved once in an
// interceptor.
func TestHostControlEvaluateRoundTrip(t *testing.T) {
	sessions := newSessionRegistry()
	var gotFacet string
	var gotAction []byte
	// What HandleConn will register when a connection starts: the same rule
	// + approve work pumpConn's EvaluateAction branch does today.
	token, remove := sessions.register(&session{
		evaluate: func(_ context.Context, facet string, action []byte, _ string) (Verdict, error) {
			gotFacet, gotAction = facet, action
			if facet == "http" {
				return Verdict{Action: "allow", Reason: "matched", Rule: "rule-1"}, nil
			}
			return Verdict{Action: "deny", Reason: "no rule"}, nil
		},
	})

	p := &ctrlTestPlugin{sessions: sessions}
	client, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{"x": p})
	defer func() { _ = client.Close() }()
	if _, err := client.Dispense("x"); err != nil {
		t.Fatalf("dispense: %v", err)
	}
	ctrl := dialHostControl(t, p)

	// The whole client side: one call, gRPC correlates the reply; the token
	// rides in metadata, not the message.
	v, err := ctrl.Evaluate(withSession(token), &pb.EvaluateRequest{
		FacetName:  "http",
		ActionJson: []byte(`{"method":"GET"}`),
		Summary:    "GET /",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if v.Action != "allow" || v.Rule != "rule-1" || v.Reason != "matched" {
		t.Fatalf("verdict = %+v, want allow/matched/rule-1", v)
	}
	if gotFacet != "http" || string(gotAction) != `{"method":"GET"}` {
		t.Fatalf("gateway saw facet=%q action=%q", gotFacet, gotAction)
	}

	// A token the gateway never issued is rejected by the interceptor — a
	// plugin cannot evaluate against a context it does not own.
	if _, err := ctrl.Evaluate(withSession("forged"), &pb.EvaluateRequest{FacetName: "http"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("forged token err = %v, want Unauthenticated", err)
	}

	// No token at all is rejected too (the method requires a session).
	if _, err := ctrl.Evaluate(context.Background(), &pb.EvaluateRequest{FacetName: "http"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing token err = %v, want Unauthenticated", err)
	}

	// Once the connection ends and its token is removed, further calls on it
	// are rejected — no dangling evaluation context.
	remove()
	if _, err := ctrl.Evaluate(withSession(token), &pb.EvaluateRequest{FacetName: "http"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("removed token err = %v, want Unauthenticated", err)
	}
}

// TestSessionRegistryTokensUnique guards the unforgeable-token property:
// minted tokens are distinct, non-empty, and only resolve while registered.
func TestSessionRegistryTokensUnique(t *testing.T) {
	r := newSessionRegistry()
	t1, rm1 := r.register(&session{})
	t2, _ := r.register(&session{})
	if t1 == t2 || t1 == "" {
		t.Fatalf("tokens not unique/non-empty: %q %q", t1, t2)
	}
	if _, ok := r.lookup(t1); !ok {
		t.Fatal("t1 should resolve while registered")
	}
	rm1()
	if _, ok := r.lookup(t1); ok {
		t.Fatal("t1 should not resolve after remove")
	}
	if _, ok := r.lookup(t2); !ok {
		t.Fatal("t2 should still resolve")
	}
}

// TestHostControlEvaluateThroughMatcher is the full wired path: a plugin
// calls HostControl.Evaluate over a real broker; the gateway resolves the
// session token, runs the connection's real rule matcher via the shared
// evaluateDecoded core, and returns the verdict — the same core the
// EvaluateAction frame handler runs.
func TestHostControlEvaluateThroughMatcher(t *testing.T) {
	m, err := facet.NewMatcher("http", "http.method == 'get'")
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	ep := &config.CompiledEndpoint{
		Name:   "ext",
		Family: "http",
		Rules: []*config.CompiledRule{
			{Name: "allow-get", Matcher: m, Outcome: config.Outcome{Verdict: "allow"}},
		},
	}
	ch := &runtime.ConnHandle{Endpoint: ep, PeerIP: "1.2.3.4"}

	sessions := newSessionRegistry()
	token, _ := sessions.register(&session{
		evaluate: func(_ context.Context, _ string, actionJSON []byte, summary string) (Verdict, error) {
			return evaluateInline(ch, nil, summary, actionJSON), nil
		},
	})

	p := &ctrlTestPlugin{sessions: sessions}
	client, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{"x": p})
	defer func() { _ = client.Close() }()
	if _, err := client.Dispense("x"); err != nil {
		t.Fatalf("dispense: %v", err)
	}
	ctrl := dialHostControl(t, p)

	// GET matches the rule → allow.
	v, err := ctrl.Evaluate(withSession(token), &pb.EvaluateRequest{
		FacetName: "http", ActionJson: []byte(`{"method":"GET"}`), Summary: "GET /",
	})
	if err != nil || v.Action != "allow" || v.Rule != "allow-get" {
		t.Fatalf("GET verdict = %+v, %v; want allow/allow-get", v, err)
	}

	// POST matches no rule → default deny.
	v, err = ctrl.Evaluate(withSession(token), &pb.EvaluateRequest{
		FacetName: "http", ActionJson: []byte(`{"method":"POST"}`), Summary: "POST /",
	})
	if err != nil || v.Action != "deny" {
		t.Fatalf("POST verdict = %+v, %v; want deny", v, err)
	}
}
