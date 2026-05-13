package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/denoland/clawpatrol/config/extplugin"
	pb "github.com/denoland/clawpatrol/config/extplugin/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
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
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: extplugin.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			extplugin.PluginName: &grpcServer{srv: srv},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// grpcServer satisfies plugin.GRPCPlugin so go-plugin registers our
// services on its server side. The client half is implemented in the
// extplugin package.
type grpcServer struct {
	plugin.NetRPCUnsupportedPlugin
	srv *server
}

func (g *grpcServer) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterPluginServer(s, g.srv)
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
	}
	for _, c := range s.plug.Credentials {
		resp.Credentials = append(resp.Credentials, &pb.CredentialDecl{
			TypeName: c.TypeName,
			Schema:   schemaToProto(c.Schema),
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
			built, err = def.Build(br)
		}
	case "tunnel":
		def, ok := s.tunnels[req.TypeName]
		if !ok {
			return nil, fmt.Errorf("%w: tunnel %q", ErrNoSuchType, req.TypeName)
		}
		if def.Build != nil {
			built, err = def.Build(br)
		}
	case "endpoint":
		def, ok := s.endpoints[req.TypeName]
		if !ok {
			return nil, fmt.Errorf("%w: endpoint %q", ErrNoSuchType, req.TypeName)
		}
		if def.Build != nil {
			built, err = def.Build(br)
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
		return resp, nil
	}

	if built != nil {
		j, jerr := json.Marshal(built)
		if jerr != nil {
			resp.Diagnostics = []*pb.Diagnostic{{
				Severity: pb.Diagnostic_ERROR,
				Summary:  "plugin returned non-JSON-serializable canonical body",
				Detail:   jerr.Error(),
			}}
			return resp, nil
		}
		resp.CanonicalJson = j
	} else {
		// Default: echo the request body so ConnInit always carries a
		// non-empty canonical_json the plugin can re-decode.
		resp.CanonicalJson = req.ConfigJson
	}
	return resp, nil
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
			default:
				// Unexpected init / event / evaluate from the gateway
				// — ignore.
			}
		}
	}()

	// Goroutine: send channel -> gateway
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case b := <-send:
				if err := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Data{
					Data: &pb.ConnData{Payload: b},
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

	handleErr := def.HandleConn(ctx, conn)
	_ = conn.Close()
	closer()
	<-recvErr
	<-sendErr

	// Best-effort final ConnClose (the gRPC layer may already be
	// torn down; ignore the error).
	if handleErr != nil {
		_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Close{
			Close: &pb.ConnClose{Reason: handleErr.Error()},
		}})
	} else {
		_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Close{
			Close: &pb.ConnClose{},
		}})
	}
	return handleErr
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

	max := int(req.MaxBytes)
	if max <= 0 || max > 64*1024 {
		max = 64 * 1024
	}
	buf := make([]byte, max)
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
		handle, err = def.Open(ctx, openReq)
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
		if err := th.def.Close(ctx, th.handle); err != nil {
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

	dialErr := th.def.Dial(ctx, TunnelDialRequest{
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
