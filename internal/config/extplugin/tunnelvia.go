package extplugin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// viaRegistry holds the PARENT tunnels a plugin's tunnels are chained
// through (`via = <tunnel>`), keyed by an opaque, unguessable token the
// gateway hands the plugin in OpenTunnelRequest.via_tunnel_handle. The
// plugin echoes the token in a HostTunnel.DialVia call to route its own
// transport connection through the parent; the gateway resolves the
// parent here and dials through it. The token IS the capability — only a
// plugin that was given a parent at OpenTunnel can reach it — so DialVia
// needs no further session scoping.
//
// One registry per plugin subprocess (Client), shared between the
// tunnelAdapter that registers parents at Open and the broker-served
// hostTunnel that resolves them at DialVia.
type viaRegistry struct {
	mu sync.Mutex
	m  map[string]runtime.Tunnel
}

func newViaRegistry() *viaRegistry {
	return &viaRegistry{m: map[string]runtime.Tunnel{}}
}

func (r *viaRegistry) add(t runtime.Tunnel) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	token := hex.EncodeToString(b[:])
	r.mu.Lock()
	r.m[token] = t
	r.mu.Unlock()
	return token
}

func (r *viaRegistry) get(token string) (runtime.Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.m[token]
	return t, ok
}

func (r *viaRegistry) remove(token string) {
	if token == "" {
		return
	}
	r.mu.Lock()
	delete(r.m, token)
	r.mu.Unlock()
}

// hostTunnel is the gateway-served HostTunnel service: it lets a tunnel
// plugin dial THROUGH its configured parent tunnel.
type hostTunnel struct {
	pb.UnimplementedHostTunnelServer
	reg *viaRegistry
}

// DialVia resolves the parent tunnel named by the init's tunnel_handle
// (a via token), dials through it, and pumps bytes between the plugin's
// stream and the parent connection. For network="udp" the payloads are
// length-prefixed datagrams end to end — the gateway is a transparent
// byte pipe, so the parent tunnel (e.g. a SOCKS plugin) is the one that
// reframes them onto a real datagram transport.
func (h *hostTunnel) DialVia(stream pb.HostTunnel_DialViaServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	if init == nil {
		return errors.New("extplugin: HostTunnel.DialVia: first message must be DialInit")
	}
	parent, ok := h.reg.get(init.GetTunnelHandle())
	if !ok {
		return errors.New("extplugin: HostTunnel.DialVia: unknown via handle (parent tunnel not open)")
	}
	conn, err := parent.Dial(stream.Context(), init.GetNetwork(), init.GetAddr())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	bridgeDialViaStream(stream, conn)
	return nil
}

// bridgeDialViaStream pumps bytes both ways between a DialVia gRPC stream
// and a parent net.Conn until either side closes.
func bridgeDialViaStream(stream pb.HostTunnel_DialViaServer, conn net.Conn) {
	done := make(chan struct{}, 2)
	// conn -> stream
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Data{
					Data: &pb.DialData{Payload: append([]byte(nil), buf[:n]...)},
				}}); serr != nil {
					break
				}
			}
			if rerr != nil {
				_ = stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Close{Close: &pb.DialClose{}}})
				break
			}
		}
		done <- struct{}{}
	}()
	// stream -> conn
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				break
			}
			switch k := msg.GetKind().(type) {
			case *pb.DialMessage_Data:
				if _, werr := conn.Write(k.Data.GetPayload()); werr != nil {
					break
				}
			case *pb.DialMessage_Close:
				_ = conn.Close()
			}
		}
		done <- struct{}{}
	}()
	<-done
	_ = conn.Close()
	<-done
}
