package extplugin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HostControl is the host-served (plugin->host) capability bundle. Unlike
// the Credential / Endpoint / Tunnel services — which the gateway calls on
// the plugin — this one runs on the gateway and a sandboxed plugin calls
// it over the go-plugin broker, alongside HostState (M1).
//
// Each plugin->gateway callback is an ordinary gRPC method, so gRPC
// correlates the reply and the hand-rolled call_id/dial_id inflight maps
// that ride inside HandleConn today disappear. The bundle grows by adding
// methods (Dial, Decide), not new frames or new services.
//
// Every call is scoped to one connection's evaluation context by an opaque
// session token the gateway minted for that connection. The token rides in
// gRPC metadata, not the message body: session scope is cross-cutting, so
// sessionUnaryInterceptor resolves it once into the request context and
// each method reads it from there — a new method is scoped for free. A
// forged / expired / removed token is rejected before the handler runs.

// sessionMetadataKey is the gRPC metadata key the per-connection session
// token rides under on every HostControl call. Lower-case per gRPC's
// metadata convention.
const sessionMetadataKey = "clawpatrol-session"

// Verdict is the gateway's decision on one Evaluate call. Mirrors
// runtime / pluginsdk.Verdict so the host-served surface and the existing
// frame path return the same shape.
type Verdict struct {
	Action string // "allow" | "deny" | "hitl_allow" | "hitl_deny" | "error"
	Reason string
	Rule   string
}

// session is one connection's control context — the work HostControl
// methods run on its behalf. Today only Evaluate; Decide and Dial join it
// as the bundle grows, reusing the same token scoping and registration.
type session struct {
	evaluate func(ctx context.Context, facetName string, actionJSON []byte, summary string) (Verdict, error)
}

// sessionRegistry maps an opaque session token to a *session, scoped to one
// plugin (each plugin gets its own registry, so a token is never valid
// across plugins). A connection registers a session when it starts and
// removes it when it ends.
type sessionRegistry struct {
	mu sync.Mutex
	m  map[string]*session
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{m: map[string]*session{}}
}

// register adds s under a fresh, unforgeable token and returns the token
// plus a remove func the caller defers when the connection ends. Minting
// the token here (crypto/rand) rather than taking it from the wire is what
// makes it unforgeable — a plugin can only present tokens the gateway
// issued to it.
func (r *sessionRegistry) register(s *session) (token string, remove func()) {
	token = newSessionToken()
	r.mu.Lock()
	r.m[token] = s
	r.mu.Unlock()
	return token, func() {
		r.mu.Lock()
		delete(r.m, token)
		r.mu.Unlock()
	}
}

func (r *sessionRegistry) lookup(token string) (*session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.m[token]
	return s, ok
}

func newSessionToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sessionCtxKey carries the resolved *session from the interceptor to the
// method handler.
type sessionCtxKey struct{}

func sessionFromContext(ctx context.Context) (*session, bool) {
	s, ok := ctx.Value(sessionCtxKey{}).(*session)
	return s, ok
}

// sessionUnaryInterceptor resolves the session token carried in request
// metadata to its *session and stashes it in the handler's context. A
// present-but-unknown token is rejected here (a plugin cannot act on a
// context it does not own); an absent token passes through unresolved, so
// non-session-scoped host services (HostState) on the same server are
// unaffected — the session-scoped methods (HostControl) require the
// session themselves via sessionFromContext.
func sessionUnaryInterceptor(reg *sessionRegistry) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if vals := md.Get(sessionMetadataKey); len(vals) > 0 {
			s, ok := reg.lookup(vals[0])
			if !ok {
				return nil, status.Error(codes.Unauthenticated, "unknown session token")
			}
			ctx = context.WithValue(ctx, sessionCtxKey{}, s)
		}
		return handler(ctx, req)
	}
}

// hostControl implements pb.HostControlServer. It is stateless: the session
// is resolved by sessionUnaryInterceptor and read from the context, so one
// instance serves every connection of a plugin.
type hostControl struct {
	pb.UnimplementedHostControlServer
}

func (hostControl) Evaluate(ctx context.Context, req *pb.EvaluateRequest) (*pb.EvaluateVerdict, error) {
	s, ok := sessionFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing session token")
	}
	v, err := s.evaluate(ctx, req.GetFacetName(), req.GetActionJson(), req.GetSummary())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "evaluate: %v", err)
	}
	return &pb.EvaluateVerdict{Action: v.Action, Reason: v.Reason, Rule: v.Rule}, nil
}

var _ pb.HostControlServer = hostControl{}
