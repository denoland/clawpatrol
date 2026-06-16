package extplugin

import (
	"context"
	"sync"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PROTOTYPE — the capability bundle (host-served control plane).
//
// HostControl is the second host-served service (alongside HostState),
// reached over the same go-plugin broker. It is the prototype home for the
// plugin->gateway *control* callbacks that today live as hand-rolled
// request/reply frames multiplexed inside the HandleConn stream — chiefly
// EvaluateAction/ActionVerdict, which on each side carries an inflight map
// keyed by a plugin-chosen call_id to match a reply to its request.
//
// As an ordinary gRPC method, Evaluate needs none of that: gRPC correlates
// the response to the call. The only new bookkeeping is a session token
// that scopes a control call to one connection's evaluation context — the
// thing a multiplexed stream got for free by virtue of the frame arriving
// on that connection's stream. sessionRegistry holds that mapping.
//
// This is a spike to evaluate the design (see
// doc/plugin-capability-bundle-prototype.md); it is not wired into the
// live HandleConn path.

// EvaluateFunc runs one action through the gateway's rule + approve chain
// for a given connection and returns the verdict. It is exactly the work
// pumpConn's EvaluateAction branch does today, lifted behind a token so it
// can be invoked from a separate channel.
type EvaluateFunc func(ctx context.Context, facetName string, actionJSON []byte, summary string) (action, reason, rule string, err error)

// sessionRegistry maps a session token to the connection's EvaluateFunc.
// A HandleConn (or its successor) registers a token when it starts a
// session and removes it when the connection ends.
type sessionRegistry struct {
	mu sync.Mutex
	m  map[string]EvaluateFunc
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{m: map[string]EvaluateFunc{}}
}

func (r *sessionRegistry) register(token string, fn EvaluateFunc) {
	r.mu.Lock()
	r.m[token] = fn
	r.mu.Unlock()
}

func (r *sessionRegistry) remove(token string) {
	r.mu.Lock()
	delete(r.m, token)
	r.mu.Unlock()
}

func (r *sessionRegistry) lookup(token string) (EvaluateFunc, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fn, ok := r.m[token]
	return fn, ok
}

// hostControl implements pb.HostControlServer for one plugin, backed by a
// per-plugin session registry.
type hostControl struct {
	pb.UnimplementedHostControlServer
	sessions *sessionRegistry
}

func newHostControl(sessions *sessionRegistry) *hostControl {
	return &hostControl{sessions: sessions}
}

func (h *hostControl) Evaluate(ctx context.Context, req *pb.EvaluateRequest) (*pb.EvaluateVerdict, error) {
	fn, ok := h.sessions.lookup(req.GetSessionToken())
	if !ok {
		// The session ended or the token was never issued — a malicious or
		// confused plugin can't evaluate against a context it doesn't own.
		return nil, status.Errorf(codes.NotFound, "unknown session token")
	}
	action, reason, rule, err := fn(ctx, req.GetFacetName(), req.GetActionJson(), req.GetSummary())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "evaluate: %v", err)
	}
	return &pb.EvaluateVerdict{Action: action, Reason: reason, Rule: rule}, nil
}

var _ pb.HostControlServer = (*hostControl)(nil)
