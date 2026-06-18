package extplugin

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sync"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// transportRouteRegistry records, per tunnel instance, how the gateway
// routes that tunnel plugin's brokered transport dials (HostTunnel.
// DialUpstream). Keyed by an opaque, unguessable token the gateway hands
// the plugin at OpenTunnel (transport_dial_handle); the plugin echoes it
// to dial. The route is the parent tunnel when the tunnel is chained
// (`via = <tunnel>`), or nil for a direct dial. The token is the
// capability — only a plugin whose gateway-side adapter registered it can
// reach the route — so DialUpstream needs no further scoping.
//
// One registry per plugin subprocess (Client), shared between the
// tunnelAdapter that registers routes at Open and the broker-served
// hostTunnel that resolves them at DialUpstream.
type transportRouteRegistry struct {
	mu sync.Mutex
	m  map[string]runtime.Tunnel // token -> parent tunnel (nil = dial direct)
}

func newTransportRouteRegistry() *transportRouteRegistry {
	return &transportRouteRegistry{m: map[string]runtime.Tunnel{}}
}

// add registers a route (parent may be nil for a direct dial) and returns
// its token.
func (r *transportRouteRegistry) add(parent runtime.Tunnel) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	token := hex.EncodeToString(b[:])
	r.mu.Lock()
	r.m[token] = parent // nil is a valid value: direct route
	r.mu.Unlock()
	return token
}

// get returns the route for a token: the parent tunnel (possibly nil for
// direct) and whether the token is registered at all.
func (r *transportRouteRegistry) get(token string) (parent runtime.Tunnel, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	parent, ok = r.m[token]
	return parent, ok
}

func (r *transportRouteRegistry) remove(token string) {
	if token == "" {
		return
	}
	r.mu.Lock()
	delete(r.m, token)
	r.mu.Unlock()
}

// hostTunnel is the gateway-served HostTunnel service: it dials a tunnel
// plugin's transport on its behalf and routes it (direct or via parent).
type hostTunnel struct {
	pb.UnimplementedHostTunnelServer
	reg *transportRouteRegistry
	// directDial dials an upstream with no parent tunnel (the gateway's
	// own dialer). Required so a tunnel plugin can run with no network of
	// its own; nil only on paths that never serve real tunnels.
	directDial func(network, addr string) (net.Conn, error)
}

// DialUpstream opens one transport connection for the calling tunnel,
// routing it through the tunnel's parent (`via`) or directly, and pumps
// bytes over the stream. For network="udp" the byte stream carries
// length-prefixed datagrams end to end; the gateway frames a real UDP
// socket on the direct path, while a chained datagram tunnel frames it on
// the via path.
func (h *hostTunnel) DialUpstream(stream pb.HostTunnel_DialUpstreamServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	if init == nil {
		return errors.New("extplugin: HostTunnel.DialUpstream: first message must be DialInit")
	}
	parent, ok := h.reg.get(init.GetTunnelHandle())
	if !ok {
		return errors.New("extplugin: HostTunnel.DialUpstream: unknown transport handle")
	}
	network, addr := init.GetNetwork(), init.GetAddr()

	var conn net.Conn
	switch {
	case parent != nil:
		// Chained: route the transport through the parent tunnel. For udp
		// the parent (e.g. a SOCKS plugin) already deals in length-prefixed
		// datagrams, so the conn is a frame-carrying byte stream.
		conn, err = parent.Dial(stream.Context(), network, addr)
	case network == "udp":
		// Direct udp: dial a real UDP socket and present it as a stream of
		// length-prefixed datagrams so the pump is uniform with the via path.
		var pc net.Conn
		pc, err = h.dial(network, addr)
		if err == nil {
			conn = newFramedDatagramConn(pc)
		}
	default:
		conn, err = h.dial(network, addr)
	}
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	bridgeTransportStream(stream, conn)
	return nil
}

func (h *hostTunnel) dial(network, addr string) (net.Conn, error) {
	if h.directDial == nil {
		return nil, errors.New("extplugin: no direct dialer wired for tunnel transport")
	}
	return h.directDial(network, addr)
}

// bridgeTransportStream pumps bytes both ways between a DialUpstream gRPC
// stream and the dialed conn until either side closes. It returns as soon
// as EITHER direction ends: closing conn unblocks the conn->stream reader,
// and returning from the handler cancels the gRPC stream — the only way to
// unblock a server-side stream.Recv. The buffered done channel lets the
// surviving goroutine exit without blocking.
func bridgeTransportStream(stream pb.HostTunnel_DialUpstreamServer, conn net.Conn) {
	// Each goroutine signals exactly once on exit (deferred, so every return
	// path counts). The channel is buffered to 2, so the surviving goroutine
	// never blocks on its send after we've already returned on the first.
	done := make(chan struct{}, 2)
	go func() { // conn -> stream
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32<<10)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Data{
					Data: &pb.DialData{Payload: append([]byte(nil), buf[:n]...)},
				}}); serr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	go func() { // stream -> conn
		defer func() { done <- struct{}{} }()
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				return
			}
			switch k := msg.GetKind().(type) {
			case *pb.DialMessage_Data:
				if _, werr := conn.Write(k.Data.GetPayload()); werr != nil {
					return
				}
			case *pb.DialMessage_Close:
				return
			}
		}
	}()
	<-done
	_ = conn.Close()
}

// framedDatagramConn presents a connected packet conn (a UDP socket) as a
// byte stream of length-prefixed datagrams, so it can be pumped over the
// broker to a plugin that reads it with pluginsdk.PacketConnOverStream.
// Read yields one framed datagram at a time; Write reassembles frames
// across arbitrary chunk boundaries and sends each as one datagram.
type framedDatagramConn struct {
	net.Conn
	rbuf []byte
	wbuf []byte
}

func newFramedDatagramConn(pc net.Conn) *framedDatagramConn {
	return &framedDatagramConn{Conn: pc}
}

func (f *framedDatagramConn) Read(p []byte) (int, error) {
	if len(f.rbuf) == 0 {
		buf := make([]byte, 64<<10)
		n, err := f.Conn.Read(buf)
		if err != nil {
			return 0, err
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(n))
		f.rbuf = append(hdr[:], buf[:n]...)
	}
	m := copy(p, f.rbuf)
	f.rbuf = f.rbuf[m:]
	return m, nil
}

func (f *framedDatagramConn) Write(p []byte) (int, error) {
	f.wbuf = append(f.wbuf, p...)
	for len(f.wbuf) >= 2 {
		n := int(binary.BigEndian.Uint16(f.wbuf[:2]))
		if len(f.wbuf) < 2+n {
			break
		}
		if _, err := f.Conn.Write(f.wbuf[2 : 2+n]); err != nil {
			return 0, err
		}
		f.wbuf = f.wbuf[2+n:]
	}
	return len(p), nil
}
