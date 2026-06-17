package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/denoland/clawpatrol/internal/config/extplugin"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

// Run blocks the caller's goroutine, serving the plugin's gRPC
// services until the gateway disconnects or sends a shutdown signal.
// Plugin authors call this from main:
//
//	func main() { pluginsdk.Run(&pluginsdk.Plugin{...}) }
func Run(p *Plugin) {
	if p == nil {
		panic("pluginsdk.Run: nil *Plugin")
	}
	if p.Name == "" {
		panic("pluginsdk.Run: Plugin.Name is required")
	}
	srv := newServer(p)
	// `<plugin> --print-manifest` prints the plugin's manifest (the same
	// one served over gRPC) as JSON and exits, without starting the gRPC
	// server. A release publishes this as a static asset so the gateway
	// can show a plugin's metadata and required privileges before it
	// downloads or runs the binary.
	if printManifestRequested() {
		if err := printManifest(os.Stdout, srv); err != nil {
			fmt.Fprintln(os.Stderr, "print-manifest:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: extplugin.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			extplugin.PluginName: &grpcServer{srv: srv},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

func printManifestRequested() bool {
	for _, a := range os.Args[1:] {
		if a == "--print-manifest" || a == "-print-manifest" {
			return true
		}
	}
	return false
}

func printManifest(w io.Writer, srv *server) error {
	resp, err := srv.Manifest(context.Background(), &pb.ManifestRequest{})
	if err != nil {
		return err
	}
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// grpcServer satisfies plugin.GRPCPlugin so go-plugin registers our
// services on its server side. The client half is implemented in the
// extplugin package.
type grpcServer struct {
	plugin.NetRPCUnsupportedPlugin
	srv *server
}

func (g *grpcServer) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	// Capture the broker so plugin code can reach the gateway's HostState
	// service (the persistent state store) via the package-level State()
	// accessor. The gateway serves it on a reserved broker stream id.
	setHostBroker(broker)
	pb.RegisterPluginServer(s, g.srv)
	pb.RegisterCredentialServer(s, g.srv)
	pb.RegisterEndpointServer(s, g.srv)
	pb.RegisterTunnelServer(s, g.srv)
	return nil
}

func (g *grpcServer) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, _ *grpc.ClientConn) (any, error) {
	// Plugins are server-only; the gateway implements the client.
	return nil, errors.New("pluginsdk: plugins do not implement the gRPC client side")
}

// server is the in-process dispatcher behind the three gRPC services.
type server struct {
	pb.UnimplementedPluginServer
	pb.UnimplementedCredentialServer
	pb.UnimplementedEndpointServer
	pb.UnimplementedTunnelServer

	plug *Plugin

	credentials map[string]CredentialDef
	tunnels     map[string]TunnelDef
	endpoints   map[string]EndpointDef

	tunHandles  sync.Map // string -> *tunnelHandle
	tunHandleID atomic.Uint64
}

func newServer(p *Plugin) *server {
	s := &server{
		plug:        p,
		credentials: make(map[string]CredentialDef, len(p.Credentials)),
		tunnels:     make(map[string]TunnelDef, len(p.Tunnels)),
		endpoints:   make(map[string]EndpointDef, len(p.Endpoints)),
	}
	for _, c := range p.Credentials {
		s.credentials[c.TypeName] = c
	}
	for _, t := range p.Tunnels {
		s.tunnels[t.TypeName] = t
	}
	for _, e := range p.Endpoints {
		s.endpoints[e.TypeName] = e
	}
	return s
}

// Manifest reports every type the plugin provides.
func (s *server) Manifest(_ context.Context, _ *pb.ManifestRequest) (*pb.ManifestResponse, error) {
	resp := &pb.ManifestResponse{
		Name:    s.plug.Name,
		Version: s.plug.Version,
		Capabilities: &pb.PluginCapabilities{
			Network: networkAccessToProto(s.plug.Capabilities.Network),
			Egress:  append([]string(nil), s.plug.Capabilities.Egress...),
		},
	}
	for _, c := range s.plug.Credentials {
		resp.Credentials = append(resp.Credentials, &pb.CredentialDecl{
			TypeName:       c.TypeName,
			Schema:         schemaToProto(c.Schema),
			Disambiguators: append([]string(nil), c.Disambiguators...),
			HttpInject:     c.HTTPInject || c.HTTPTransform,
			HttpTransform:  c.HTTPTransform,
		})
	}
	for _, t := range s.plug.Tunnels {
		resp.Tunnels = append(resp.Tunnels, &pb.TunnelDecl{
			TypeName: t.TypeName,
			Schema:   schemaToProto(t.Schema),
		})
	}
	for _, e := range s.plug.Endpoints {
		resp.Endpoints = append(resp.Endpoints, &pb.EndpointDecl{
			TypeName:    e.TypeName,
			Schema:      schemaToProto(e.Schema),
			Family:      e.Family,
			TlsMode:     pb.TLSMode(e.TLSMode),
			RequiresVip: e.RequiresVIP,
		})
	}
	for _, f := range s.plug.Facets {
		fields := make([]*pb.FacetFieldDecl, 0, len(f.Fields))
		for _, fld := range f.Fields {
			fields = append(fields, &pb.FacetFieldDecl{
				Name:     fld.Name,
				Kind:     pb.FacetKind(fld.Kind),
				Label:    fld.Label,
				Optional: fld.Optional,
			})
		}
		resp.Facets = append(resp.Facets, &pb.FacetDecl{Name: f.Name, Fields: fields})
	}
	return resp, nil
}

func networkAccessToProto(n NetworkAccess) pb.NetworkAccess {
	if n == NetworkOutbound {
		return pb.NetworkAccess_NETWORK_OUTBOUND
	}
	return pb.NetworkAccess_NETWORK_NONE
}

func schemaToProto(s Schema) *pb.Schema {
	p := &pb.Schema{}
	for _, f := range s.Fields {
		p.Fields = append(p.Fields, &pb.SchemaField{
			Name:       f.Name,
			TypeString: f.TypeString,
			Required:   f.Required,
		})
	}
	return p
}

// Build dispatches to the plugin's per-kind callback. When the
// plugin doesn't supply a Build, the SDK echoes the request body
// unchanged — which is fine for credentials / tunnels whose only
// "validation" is whatever HCL already enforces.
func (s *server) Build(_ context.Context, req *pb.BuildRequest) (*pb.BuildResponse, error) {
	br := BuildRequest{
		Kind:         req.Kind,
		TypeName:     req.TypeName,
		InstanceName: req.InstanceName,
		ConfigJSON:   req.ConfigJson,
	}

	var (
		built any
		err   error
	)
	switch req.Kind {
	case "credential":
		def, ok := s.credentials[req.TypeName]
		if !ok {
			return nil, fmt.Errorf("%w: credential %q", ErrNoSuchType, req.TypeName)
		}
		if def.Build != nil {
			built, err = invokeBuild("credential", req.TypeName, req.InstanceName, def.Build, br)
		}
	case "tunnel":
		def, ok := s.tunnels[req.TypeName]
		if !ok {
			return nil, fmt.Errorf("%w: tunnel %q", ErrNoSuchType, req.TypeName)
		}
		if def.Build != nil {
			built, err = invokeBuild("tunnel", req.TypeName, req.InstanceName, def.Build, br)
		}
	case "endpoint":
		def, ok := s.endpoints[req.TypeName]
		if !ok {
			return nil, fmt.Errorf("%w: endpoint %q", ErrNoSuchType, req.TypeName)
		}
		if def.Build != nil {
			built, err = invokeBuild("endpoint", req.TypeName, req.InstanceName, def.Build, br)
		}
	default:
		return nil, fmt.Errorf("pluginsdk: unknown build kind %q", req.Kind)
	}

	resp := &pb.BuildResponse{}
	if err != nil {
		resp.Diagnostics = []*pb.Diagnostic{{
			Severity: pb.Diagnostic_ERROR,
			Summary:  fmt.Sprintf("plugin build failed for %s.%s %q", req.Kind, req.TypeName, req.InstanceName),
			Detail:   err.Error(),
		}}
		return resp, nil //nolint:nilerr // Build errors are returned as diagnostics in the successful gRPC response.
	}

	canonical := built
	if req.Kind == "credential" {
		switch r := built.(type) {
		case CredentialBuildResult:
			canonical = r.Canonical
			resp.CredentialMetadata = credentialMetadataToProto(r.Metadata)
		case *CredentialBuildResult:
			if r != nil {
				canonical = r.Canonical
				resp.CredentialMetadata = credentialMetadataToProto(r.Metadata)
			}
		}
	}

	if canonical != nil {
		j, jerr := json.Marshal(canonical)
		if jerr != nil {
			resp.Diagnostics = []*pb.Diagnostic{{
				Severity: pb.Diagnostic_ERROR,
				Summary:  "plugin returned non-JSON-serializable canonical body",
				Detail:   jerr.Error(),
			}}
			return resp, nil //nolint:nilerr // JSON serialization errors are returned as diagnostics in the successful gRPC response.
		}
		resp.CanonicalJson = j
	} else {
		// Default: echo the request body so ConnInit always carries a
		// non-empty canonical_json the plugin can re-decode.
		resp.CanonicalJson = req.ConfigJson
	}
	return resp, nil
}

func invokeBuild(kind, typeName, instanceName string, fn func(BuildRequest) (any, error), req BuildRequest) (built any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = callbackPanicError(fmt.Sprintf("%s.%s %q Build", kind, typeName, instanceName), r)
		}
	}()
	return fn(req)
}

func credentialMetadataToProto(m CredentialMetadata) *pb.CredentialMetadata {
	out := &pb.CredentialMetadata{
		Disambiguators: append([]string(nil), m.Disambiguators...),
		HttpInject:     m.HTTPInject || m.HTTPTransform,
		HttpTransform:  m.HTTPTransform,
	}
	for _, s := range m.SecretSlots {
		out.SecretSlots = append(out.SecretSlots, &pb.SecretSlotDecl{
			Name:        s.Name,
			Label:       s.Label,
			Multiline:   s.Multiline,
			Description: s.Description,
		})
	}
	for _, ev := range m.EnvVars {
		out.EnvVars = append(out.EnvVars, &pb.EnvVarDecl{
			Name:        ev.Name,
			Value:       ev.Value,
			Description: ev.Description,
		})
	}
	if m.OAuth != nil {
		out.Oauth = oauthIntegrationToProto(*m.OAuth)
	}
	return out
}

func oauthIntegrationToProto(in OAuthIntegration) *pb.OAuthIntegrationDecl {
	out := &pb.OAuthIntegrationDecl{
		Type:   in.Type,
		Header: in.Header,
		Prefix: in.Prefix,
		Flow:   in.Flow,
		Oauth: &pb.OAuthConfigDecl{
			ClientId:     in.OAuth.ClientID,
			ClientSecret: in.OAuth.ClientSecret,
			AuthUrl:      in.OAuth.AuthURL,
			TokenUrl:     in.OAuth.TokenURL,
			DeviceUrl:    in.OAuth.DeviceURL,
			RegisterUrl:  in.OAuth.RegisterURL,
			RedirectUri:  in.OAuth.RedirectURI,
			Scopes:       append([]string(nil), in.OAuth.Scopes...),
			RefreshToken: in.OAuth.RefreshToken,
		},
	}
	for _, g := range in.OptionalScopes {
		pg := &pb.OptionalScopeGroupDecl{Title: g.Title}
		for _, s := range g.Scopes {
			pg.Scopes = append(pg.Scopes, &pb.OptionalScopeDecl{Id: s.ID, Label: s.Label})
		}
		out.OptionalScopes = append(out.OptionalScopes, pg)
	}
	return out
}

// InjectHTTP dispatches a built-in HTTPS credential injection call to
// the credential definition's callback.
func (s *server) InjectHTTP(ctx context.Context, req *pb.InjectHTTPRequest) (*pb.InjectHTTPResponse, error) {
	def, ok := s.credentials[req.CredentialTypeName]
	if !ok {
		return nil, fmt.Errorf("%w: credential %q", ErrNoSuchType, req.CredentialTypeName)
	}
	if def.InjectHTTP == nil {
		return nil, fmt.Errorf("pluginsdk: credential %q has no InjectHTTP callback", req.CredentialTypeName)
	}
	in := HTTPInjectRequest{
		CredentialTypeName:        req.CredentialTypeName,
		CredentialInstance:        req.CredentialInstance,
		CredentialCanonicalConfig: req.CredentialCanonicalJson,
		CredentialSecret:          req.CredentialSecret,
		CredentialExtras:          req.CredentialExtras,
		Method:                    req.Method,
		URL:                       req.Url,
		Host:                      req.Host,
		Headers:                   headersFromProto(req.Headers),
		BodyPrefix:                req.BodyPrefix,
		BodyTruncated:             req.BodyTruncated,
	}
	out, err := invokeInjectHTTP(ctx, req.CredentialTypeName, req.CredentialInstance, def.InjectHTTP, in)
	if err != nil {
		return nil, err
	}
	return httpInjectResponseToProto(out), nil
}

func invokeInjectHTTP(ctx context.Context, typeName, instanceName string, fn func(context.Context, HTTPInjectRequest) (*HTTPInjectResponse, error), req HTTPInjectRequest) (out *HTTPInjectResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = callbackPanicError(fmt.Sprintf("credential.%s %q InjectHTTP", typeName, instanceName), r)
		}
	}()
	return fn(ctx, req)
}

func headersFromProto(in map[string]*pb.HTTPHeaderValues) http.Header {
	out := http.Header{}
	for k, v := range in {
		if v == nil {
			continue
		}
		out[k] = append([]string(nil), v.Values...)
	}
	return out
}

func httpInjectResponseToProto(in *HTTPInjectResponse) *pb.InjectHTTPResponse {
	out := &pb.InjectHTTPResponse{}
	if in == nil {
		return out
	}
	for _, h := range in.Headers {
		op := pb.HeaderMutation_SET
		switch h.Op {
		case HeaderAdd:
			op = pb.HeaderMutation_ADD
		case HeaderDel:
			op = pb.HeaderMutation_DEL
		}
		out.Headers = append(out.Headers, &pb.HeaderMutation{
			Op:     op,
			Name:   h.Name,
			Values: append([]string(nil), h.Values...),
		})
	}
	out.Redactions = append([]string(nil), in.Redactions...)
	return out
}

// dialState is the SDK-side bookkeeping for one brokered upstream
// dial. reply and recv are closed only by the HandleConn recv
// goroutine (their sole sender); done is closed on local Close.
type dialState struct {
	reply chan *pb.DialUpstreamReply
	recv  chan []byte
	done  chan struct{}
	once  sync.Once
}

func (d *dialState) localClose() {
	d.once.Do(func() { close(d.done) })
}

// HandleConn pumps the gateway-provided agent connection to the
// EndpointDef.HandleConn callback. Sequence:
//
//  1. Receive the ConnInit message. Look up the endpoint def.
//  2. Spin up a *Conn that exposes the bidi stream as a net.Conn.
//  3. Run def.HandleConn(ctx, conn) until it returns.
//  4. Drain remaining frames + send a final ConnClose.
func (s *server) HandleConn(stream pb.Endpoint_HandleConnServer) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("pluginsdk HandleConn: recv init: %w", err)
	}
	init, ok := first.GetKind().(*pb.ConnMessage_Init)
	if !ok || init.Init == nil {
		return errors.New("pluginsdk HandleConn: first message must be ConnInit")
	}
	in := init.Init
	def, ok := s.endpoints[in.EndpointTypeName]
	if !ok {
		return fmt.Errorf("%w: endpoint %q", ErrNoSuchType, in.EndpointTypeName)
	}

	recv := make(chan []byte, 16)
	send := make(chan []byte, 16)
	closed := make(chan struct{})
	closeOnce := sync.Once{}
	closer := func() { closeOnce.Do(func() { close(closed) }) }

	conn := &Conn{
		Conn: newStreamConn(recv, send, closer,
			fakeAddr{name: "gateway"}, fakeAddr{name: in.PeerIp}),
		EndpointTypeName:          in.EndpointTypeName,
		EndpointInstance:          in.EndpointInstance,
		EndpointCanonicalConfig:   in.EndpointCanonicalJson,
		Profile:                   in.Profile,
		PeerIP:                    in.PeerIp,
		UpstreamHost:              in.UpstreamHost,
		DstPort:                   uint16(in.DstPort),
		CredentialTypeName:        in.CredentialTypeName,
		CredentialInstance:        in.CredentialInstance,
		CredentialSecret:          in.CredentialSecret,
		CredentialExtras:          in.CredentialExtras,
		CredentialCanonicalConfig: in.CredentialCanonicalJson,
		Credentials:               connCredentialsFromProto(in.Credentials),
		TunnelTypeName:            in.TunnelTypeName,
		TunnelInstance:            in.TunnelInstance,
	}
	// sendMu serializes stream.Send across emit / evaluate / data
	// pumps. gRPC server streams aren't safe for concurrent Send.
	var sendMu sync.Mutex
	doSend := func(m *pb.ConnMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}

	conn.emit = func(ev ConnEvent) {
		facets, _ := json.Marshal(ev.Facets)
		_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Event{Event: &pb.ConnEvent{
			Action:     ev.Action,
			Reason:     ev.Reason,
			Verb:       ev.Verb,
			Summary:    ev.Summary,
			BytesCount: ev.Bytes,
			FacetsJson: facets,
			Rule:       ev.Rule,
		}}})
	}

	// inflight tracks Conn.Evaluate calls awaiting an ActionVerdict
	// from the gateway. The recv goroutine routes verdicts here by
	// call_id; the Evaluate caller blocks on its channel until the
	// gateway replies (or the conn closes).
	var inflightMu sync.Mutex
	inflight := map[string]chan *pb.ActionVerdict{}
	var callSeq atomic.Uint64

	// streams holds active StreamValue readers keyed by handle. The
	// recv goroutine fulfils gateway StreamRead requests by reading
	// from the registered io.Reader and replying with StreamChunk;
	// StreamCancel drops the entry so the plugin's source goroutine
	// notices on the next read.
	var streamsMu sync.Mutex
	streams := map[string]*streamReg{}
	var streamSeq atomic.Uint64

	// dials tracks brokered upstream connections (Conn.DialUpstream)
	// keyed by dial_id. The recv goroutine routes DialUpstreamReply /
	// Data / Close frames here; reg.recv is closed only by the recv
	// goroutine (its sole sender), so readers get a clean io.EOF.
	var dialsMu sync.Mutex
	dials := map[string]*dialState{}
	var dialSeq atomic.Uint64

	conn.evaluate = func(ctx context.Context, facet string, action map[string]any, summary string) (Verdict, error) {
		// Pull StreamValue entries out of the action map, allocate a
		// handle for each, register the reader, and replace the
		// action-map entry with nil so the JSON payload is small.
		// Stream entries roll up into EvaluateAction.streams instead.
		actionForJSON := action
		streamHandles := map[string]string(nil)
		for k, v := range action {
			sv, ok := v.(StreamValue)
			if !ok {
				continue
			}
			if streamHandles == nil {
				// Lazy clone so we don't mutate the caller's map.
				actionForJSON = make(map[string]any, len(action))
				for kk, vv := range action {
					if _, isStream := vv.(StreamValue); isStream {
						actionForJSON[kk] = nil
					} else {
						actionForJSON[kk] = vv
					}
				}
				streamHandles = map[string]string{}
			}
			handle := fmt.Sprintf("s%d", streamSeq.Add(1))
			streamsMu.Lock()
			streams[handle] = &streamReg{r: sv.R}
			streamsMu.Unlock()
			streamHandles[k] = handle
		}

		j, err := json.Marshal(actionForJSON)
		if err != nil {
			return Verdict{}, fmt.Errorf("pluginsdk: marshal action: %w", err)
		}
		callID := fmt.Sprintf("c%d", callSeq.Add(1))
		ch := make(chan *pb.ActionVerdict, 1)
		inflightMu.Lock()
		inflight[callID] = ch
		inflightMu.Unlock()
		defer func() {
			inflightMu.Lock()
			delete(inflight, callID)
			inflightMu.Unlock()
			// Drop any streams the gateway didn't explicitly cancel —
			// the call is done, the readers are no longer interesting.
			if len(streamHandles) > 0 {
				streamsMu.Lock()
				for _, h := range streamHandles {
					delete(streams, h)
				}
				streamsMu.Unlock()
			}
		}()
		if err := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Evaluate{Evaluate: &pb.EvaluateAction{
			CallId:     callID,
			FacetName:  facet,
			ActionJson: j,
			Summary:    summary,
			Streams:    streamHandles,
		}}}); err != nil {
			return Verdict{}, fmt.Errorf("pluginsdk: send EvaluateAction: %w", err)
		}
		select {
		case v := <-ch:
			if v == nil {
				return Verdict{}, errors.New("pluginsdk: connection closed before verdict")
			}
			return Verdict{Action: v.Action, Reason: v.Reason, Rule: v.Rule}, nil
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		case <-closed:
			return Verdict{}, errors.New("pluginsdk: connection closed before verdict")
		}
	}

	conn.dialUpstream = func(ctx context.Context, network, addr string, opts *DialUpstreamOptions) (net.Conn, error) {
		if !in.SupportsDialUpstream {
			return nil, ErrDialUpstreamUnsupported
		}
		id := fmt.Sprintf("d%d", dialSeq.Add(1))
		reg := &dialState{
			reply: make(chan *pb.DialUpstreamReply, 1),
			recv:  make(chan []byte, 16),
			done:  make(chan struct{}),
		}
		dialsMu.Lock()
		dials[id] = reg
		dialsMu.Unlock()
		unregister := func() {
			dialsMu.Lock()
			delete(dials, id)
			dialsMu.Unlock()
		}
		req := &pb.DialUpstreamRequest{DialId: id, Network: network, Addr: addr}
		if opts != nil {
			req.Tls = opts.TLS
			req.TlsServerName = opts.TLSServerName
		}
		if err := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialRequest{DialRequest: req}}); err != nil {
			unregister()
			return nil, fmt.Errorf("pluginsdk: send DialUpstreamRequest: %w", err)
		}
		select {
		case r, ok := <-reg.reply:
			if !ok {
				return nil, errors.New("pluginsdk: connection closed before dial reply")
			}
			if r.Error != "" {
				unregister()
				return nil, fmt.Errorf("pluginsdk: dial %s: %s", addr, r.Error)
			}
		case <-ctx.Done():
			unregister()
			// The gateway may have already opened the upstream and a
			// reply may be racing in; tell it to tear the dial down
			// now rather than leaking it until the idle timeout. The
			// conn itself is still up, so this send is worthwhile.
			_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialClose{DialClose: &pb.DialUpstreamClose{DialId: id}}})
			return nil, ctx.Err()
		case <-closed:
			unregister()
			return nil, errors.New("pluginsdk: connection closed before dial reply")
		}

		// Per-dial sender: drains the conn's write channel into
		// DialUpstreamData frames.
		dialSend := make(chan []byte, 16)
		go func() {
			for {
				select {
				case b := <-dialSend:
					if err := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialData{DialData: &pb.DialUpstreamData{
						DialId: id, Payload: b,
					}}}); err != nil {
						reg.localClose()
						return
					}
				case <-reg.done:
					return
				case <-closed:
					return
				}
			}
		}()
		closeFn := func() {
			reg.localClose()
			_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialClose{DialClose: &pb.DialUpstreamClose{DialId: id}}})
		}
		return newStreamConn(reg.recv, dialSend, closeFn,
			fakeAddr{name: "plugin"}, fakeAddr{name: addr}), nil
	}

	// Goroutine: gateway -> recv channel
	recvErr := make(chan error, 1)
	go func() {
		defer close(recv)
		// On exit, fail any pending Evaluate calls so callers
		// blocked on ch unblock instead of leaking goroutines.
		defer func() {
			inflightMu.Lock()
			for id, ch := range inflight {
				close(ch)
				delete(inflight, id)
			}
			inflightMu.Unlock()
			streamsMu.Lock()
			for h, reg := range streams {
				reg.cancel()
				delete(streams, h)
			}
			streamsMu.Unlock()
			// Fail pending DialUpstream callers and EOF open dial
			// conns. Safe: this goroutine is the sole sender on
			// reply / recv.
			dialsMu.Lock()
			for id, reg := range dials {
				close(reg.reply)
				close(reg.recv)
				delete(dials, id)
			}
			dialsMu.Unlock()
		}()
		for {
			msg, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					recvErr <- nil
				} else {
					recvErr <- err
				}
				return
			}
			switch k := msg.GetKind().(type) {
			case *pb.ConnMessage_Data:
				select {
				case recv <- k.Data.Payload:
				case <-closed:
					recvErr <- nil
					return
				}
			case *pb.ConnMessage_Close:
				recvErr <- nil
				return
			case *pb.ConnMessage_Verdict:
				inflightMu.Lock()
				ch, ok := inflight[k.Verdict.CallId]
				if ok {
					delete(inflight, k.Verdict.CallId)
				}
				inflightMu.Unlock()
				if ok {
					ch <- k.Verdict
				}
			case *pb.ConnMessage_StreamRead:
				// Read up to max_bytes from the registered reader and
				// reply with one StreamChunk. Run in a goroutine so a
				// slow reader doesn't stall verdict / data messages
				// queued after this read on the same gRPC stream.
				go serveStreamRead(k.StreamRead, &streamsMu, streams, doSend)
			case *pb.ConnMessage_StreamCancel:
				streamsMu.Lock()
				if reg, ok := streams[k.StreamCancel.Handle]; ok {
					reg.cancel()
					delete(streams, k.StreamCancel.Handle)
				}
				streamsMu.Unlock()
			case *pb.ConnMessage_DialReply:
				dialsMu.Lock()
				reg := dials[k.DialReply.DialId]
				dialsMu.Unlock()
				if reg != nil {
					select {
					case reg.reply <- k.DialReply:
					default:
						// Duplicate reply — drop.
					}
				}
			case *pb.ConnMessage_DialData:
				dialsMu.Lock()
				reg := dials[k.DialData.DialId]
				dialsMu.Unlock()
				if reg != nil {
					select {
					case reg.recv <- k.DialData.Payload:
					case <-reg.done:
					case <-closed:
					}
				}
			case *pb.ConnMessage_DialClose:
				dialsMu.Lock()
				reg := dials[k.DialClose.DialId]
				delete(dials, k.DialClose.DialId)
				dialsMu.Unlock()
				if reg != nil {
					close(reg.recv) // readers see io.EOF
				}
			default:
				// Unexpected init / event / evaluate from the gateway
				// — ignore.
			}
		}
	}()

	// Goroutine: send channel -> gateway
	sendErr := make(chan error, 1)
	go func() {
		forward := func(b []byte) error {
			return doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Data{
				Data: &pb.ConnData{Payload: b},
			}})
		}
		for {
			select {
			case b := <-send:
				if err := forward(b); err != nil {
					sendErr <- err
					return
				}
			case <-closed:
				// Flush any bytes the handler wrote just before it
				// returned (Write only buffers onto `send`), so a
				// response isn't truncated by the teardown.
				for {
					select {
					case b := <-send:
						if err := forward(b); err != nil {
							sendErr <- err
							return
						}
					default:
						sendErr <- nil
						return
					}
				}
			}
		}
	}()

	handleErr := invokeHandleConn(ctx, def, conn)
	_ = conn.Close()
	closer()

	// Wait for the send goroutine to flush every queued response byte
	// before announcing the close, so the agent sees a complete
	// response and not a truncated one.
	<-sendErr

	// Then tell the gateway we're done. This must happen before we
	// wait on the recv goroutine: it is blocked in stream.Recv() and
	// only unblocks when the gateway tears the stream down — which it
	// does in response to this ConnClose. Sending it after <-recvErr
	// would deadlock when the handler returns before the agent closes
	// the connection (e.g. an upstream dial was refused), since the
	// gateway is simultaneously waiting on us to send it.
	closeMsg := &pb.ConnClose{}
	if handleErr != nil {
		closeMsg.Reason = handleErr.Error()
	}
	_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Close{Close: closeMsg}})

	<-recvErr
	return handleErr
}

func invokeHandleConn(ctx context.Context, def EndpointDef, conn *Conn) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = callbackPanicError(fmt.Sprintf("endpoint.%s HandleConn", def.TypeName), r)
		}
	}()
	if def.HandleConn == nil {
		return fmt.Errorf("pluginsdk: endpoint %q has no HandleConn callback", def.TypeName)
	}
	return def.HandleConn(ctx, conn)
}

func invokeTunnelOpen(ctx context.Context, def TunnelDef, req TunnelOpenRequest) (handle any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = callbackPanicError(fmt.Sprintf("tunnel.%s %q Open", def.TypeName, req.TunnelInstance), r)
		}
	}()
	return def.Open(ctx, req)
}

func invokeTunnelClose(ctx context.Context, def TunnelDef, handle any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = callbackPanicError(fmt.Sprintf("tunnel.%s Close", def.TypeName), r)
		}
	}()
	return def.Close(ctx, handle)
}

func invokeTunnelDial(ctx context.Context, def TunnelDef, req TunnelDialRequest, conn net.Conn) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = callbackPanicError(fmt.Sprintf("tunnel.%s Dial", def.TypeName), r)
		}
	}()
	return def.Dial(ctx, req, conn)
}

func callbackPanicError(where string, r any) error {
	return fmt.Errorf("pluginsdk: panic in %s: %v\n%s", where, r, debug.Stack())
}

// streamReg holds one StreamValue's reader plus a cancel sentinel
// the recv goroutine flips on StreamCancel. The serveStreamRead
// helper checks cancelled before each read so a slow reader can't
// re-enable a stream the gateway already abandoned.
type streamReg struct {
	r         io.Reader
	mu        sync.Mutex
	cancelled bool
}

func (s *streamReg) cancel() {
	s.mu.Lock()
	s.cancelled = true
	s.mu.Unlock()
	if c, ok := s.r.(io.Closer); ok {
		_ = c.Close()
	}
}

// serveStreamRead replies to one gateway StreamRead by reading from
// the registered io.Reader and sending a single StreamChunk. eof is
// set when the reader returns io.EOF or the stream was cancelled.
// Errors get logged via a final eof chunk so the gateway doesn't
// hang waiting for more.
func serveStreamRead(req *pb.StreamRead, mu *sync.Mutex, streams map[string]*streamReg, doSend func(*pb.ConnMessage) error) {
	mu.Lock()
	reg, ok := streams[req.Handle]
	mu.Unlock()
	if !ok {
		_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_StreamChunk{StreamChunk: &pb.StreamChunk{
			Handle: req.Handle, Eof: true,
		}}})
		return
	}
	reg.mu.Lock()
	if reg.cancelled {
		reg.mu.Unlock()
		_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_StreamChunk{StreamChunk: &pb.StreamChunk{
			Handle: req.Handle, Eof: true,
		}}})
		return
	}
	reg.mu.Unlock()

	limit := int(req.MaxBytes)
	if limit <= 0 || limit > 64*1024 {
		limit = 64 * 1024
	}
	buf := make([]byte, limit)
	n, err := reg.r.Read(buf)
	chunk := &pb.StreamChunk{Handle: req.Handle, Payload: buf[:n]}
	if err != nil {
		// io.EOF or any read error is terminal. Forward what we got
		// (may be 0 bytes) plus eof; the gateway treats both errors
		// and EOF the same — the stream is done.
		chunk.Eof = true
		mu.Lock()
		delete(streams, req.Handle)
		mu.Unlock()
	}
	_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_StreamChunk{StreamChunk: chunk}})
}

// tunnelHandle is the SDK's record of one OpenTunnel call. The
// plugin's Open returns the inner Handle (any); the SDK stores it
// keyed by an opaque string the gateway uses on subsequent Dial /
// CloseTunnel calls.
type tunnelHandle struct {
	def    TunnelDef
	handle any
}

func (s *server) OpenTunnel(ctx context.Context, req *pb.OpenTunnelRequest) (*pb.OpenTunnelResponse, error) {
	def, ok := s.tunnels[req.TunnelTypeName]
	if !ok {
		return nil, fmt.Errorf("%w: tunnel %q", ErrNoSuchType, req.TunnelTypeName)
	}
	openReq := TunnelOpenRequest{
		TunnelTypeName:   req.TunnelTypeName,
		TunnelInstance:   req.TunnelInstance,
		CanonicalConfig:  req.CanonicalJson,
		CredentialSecret: req.CredentialSecret,
		CredentialExtras: req.CredentialExtras,
	}
	var (
		handle any
		err    error
	)
	if def.Open != nil {
		handle, err = invokeTunnelOpen(ctx, def, openReq)
		if err != nil {
			return nil, fmt.Errorf("plugin tunnel %q open: %w", req.TunnelInstance, err)
		}
	} else {
		handle = req.TunnelInstance
	}
	id := fmt.Sprintf("t%d-%s", s.tunHandleID.Add(1), req.TunnelInstance)
	s.tunHandles.Store(id, &tunnelHandle{def: def, handle: handle})
	return &pb.OpenTunnelResponse{Handle: id}, nil
}

func (s *server) CloseTunnel(ctx context.Context, req *pb.CloseTunnelRequest) (*pb.CloseTunnelResponse, error) {
	v, ok := s.tunHandles.LoadAndDelete(req.Handle)
	if !ok {
		return &pb.CloseTunnelResponse{}, nil
	}
	th := v.(*tunnelHandle)
	if th.def.Close != nil {
		if err := invokeTunnelClose(ctx, th.def, th.handle); err != nil {
			return nil, err
		}
	}
	return &pb.CloseTunnelResponse{}, nil
}

func (s *server) Dial(stream pb.Tunnel_DialServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("pluginsdk Dial: recv init: %w", err)
	}
	initMsg, ok := first.GetKind().(*pb.DialMessage_Init)
	if !ok || initMsg.Init == nil {
		return errors.New("pluginsdk Dial: first message must be DialInit")
	}
	v, ok := s.tunHandles.Load(initMsg.Init.TunnelHandle)
	if !ok {
		return fmt.Errorf("pluginsdk Dial: unknown tunnel handle %q", initMsg.Init.TunnelHandle)
	}
	th := v.(*tunnelHandle)
	if th.def.Dial == nil {
		return fmt.Errorf("pluginsdk Dial: tunnel %q has no Dial callback", th.def.TypeName)
	}

	recv := make(chan []byte, 16)
	send := make(chan []byte, 16)
	closed := make(chan struct{})
	closeOnce := sync.Once{}
	closer := func() { closeOnce.Do(func() { close(closed) }) }

	upstream := newStreamConn(recv, send, closer,
		fakeAddr{name: "tunnel"}, fakeAddr{name: initMsg.Init.Addr})

	recvErr := make(chan error, 1)
	go func() {
		defer close(recv)
		for {
			msg, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					recvErr <- nil
				} else {
					recvErr <- err
				}
				return
			}
			switch k := msg.GetKind().(type) {
			case *pb.DialMessage_Data:
				select {
				case recv <- k.Data.Payload:
				case <-closed:
					recvErr <- nil
					return
				}
			case *pb.DialMessage_Close:
				recvErr <- nil
				return
			}
		}
	}()
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case b := <-send:
				if err := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Data{
					Data: &pb.DialData{Payload: b},
				}}); err != nil {
					sendErr <- err
					return
				}
			case <-closed:
				sendErr <- nil
				return
			}
		}
	}()

	dialErr := invokeTunnelDial(ctx, th.def, TunnelDialRequest{
		Handle:  th.handle,
		Network: initMsg.Init.Network,
		Addr:    initMsg.Init.Addr,
	}, upstream)
	_ = upstream.Close()
	closer()
	<-recvErr
	<-sendErr

	if dialErr != nil {
		_ = stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Close{Close: &pb.DialClose{Reason: dialErr.Error()}}})
	} else {
		_ = stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Close{Close: &pb.DialClose{}}})
	}
	return dialErr
}

// connCredentialsFromProto maps the repeated BoundCredential set carried on
// ConnInit to the SDK's ConnCredential slice. Returns nil when the gateway
// sent none (older gateways, or an endpoint with no credential) — callers
// then fall back to the singular Conn.Credential* fields.
func connCredentialsFromProto(in []*pb.BoundCredential) []ConnCredential {
	if len(in) == 0 {
		return nil
	}
	out := make([]ConnCredential, 0, len(in))
	for _, c := range in {
		if c == nil {
			continue
		}
		out = append(out, ConnCredential{
			TypeName:        c.TypeName,
			Instance:        c.Instance,
			Secret:          c.Secret,
			Extras:          c.Extras,
			CanonicalConfig: c.CanonicalJson,
		})
	}
	return out
}
