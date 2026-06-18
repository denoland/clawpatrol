package pluginsdk

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

// DialUpstreamFunc opens a tunnel plugin's transport connection — the
// socket the tunnel rides on to reach its endpoint (the TCP conn to an
// SSH bastion, the UDP conn to a WireGuard endpoint). It is the
// tunnel-side equivalent of an endpoint plugin's Conn.DialUpstream: the
// gateway dials on the plugin's behalf and routes it directly, or — when
// the tunnel is chained (`via = <tunnel>`) — through the parent tunnel.
// The plugin never knows the route, so a tunnel plugin should run with no
// network capability of its own and dial only through this.
//
// network is "tcp" for a stream transport or "udp" for a datagram
// transport. For "udp" the returned conn carries length-prefixed
// datagrams (write one whole packet per Write, read one per Read); wrap
// it with PacketConnOverStream for a net.PacketConn view.
type DialUpstreamFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// transportDialer builds the DialUpstream closure bound to a tunnel's
// transport_dial_handle. Returns nil when the handle is empty (an old
// gateway, or a non-tunnel path).
func transportDialer(handle string) DialUpstreamFunc {
	if handle == "" {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		cli, err := hostTunnelClient()
		if err != nil {
			return nil, err
		}
		stream, err := cli.DialUpstream(ctx)
		if err != nil {
			return nil, err
		}
		if err := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Init{Init: &pb.DialInit{
			TunnelHandle: handle,
			Network:      network,
			Addr:         addr,
		}}}); err != nil {
			return nil, err
		}
		return &transportConn{stream: stream, addr: addr}, nil
	}
}

func hostTunnelClient() (pb.HostTunnelClient, error) {
	c, err := hostServicesConn()
	if err != nil {
		return nil, err
	}
	return pb.NewHostTunnelClient(c), nil
}

// transportConn wraps a HostTunnel.DialUpstream bidi stream as a net.Conn
// (the client-side mirror of the gateway's dialConn).
type transportConn struct {
	stream pb.HostTunnel_DialUpstreamClient
	addr   string

	mu      sync.Mutex
	readBuf []byte
	closed  bool
	wMu     sync.Mutex
	once    sync.Once
}

func (c *transportConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	for {
		msg, err := c.stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}
		switch k := msg.GetKind().(type) {
		case *pb.DialMessage_Data:
			n := copy(p, k.Data.Payload)
			if n < len(k.Data.Payload) {
				c.mu.Lock()
				c.readBuf = append(c.readBuf, k.Data.Payload[n:]...)
				c.mu.Unlock()
			}
			return n, nil
		case *pb.DialMessage_Close:
			return 0, io.EOF
		}
	}
}

func (c *transportConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if err := c.stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Data{
		Data: &pb.DialData{Payload: append([]byte(nil), p...)},
	}}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *transportConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		_ = c.stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Close{Close: &pb.DialClose{}}})
		_ = c.stream.CloseSend()
	})
	return nil
}

func (c *transportConn) LocalAddr() net.Addr                { return transportAddr("transport") }
func (c *transportConn) RemoteAddr() net.Addr               { return transportAddr(c.addr) }
func (c *transportConn) SetDeadline(_ time.Time) error      { return nil }
func (c *transportConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *transportConn) SetWriteDeadline(_ time.Time) error { return nil }

type transportAddr string

func (a transportAddr) Network() string { return "plugin-tunnel-transport" }
func (a transportAddr) String() string  { return string(a) }
