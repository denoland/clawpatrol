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

// TunnelVia routes a chained tunnel's own transport connection through
// its parent tunnel (`via = <tunnel>`). The gateway hands the plugin an
// opaque handle at OpenTunnel; Dial echoes it to the gateway's
// HostTunnel.DialVia, which resolves the parent and dials through it.
//
// network is "tcp" for a stream transport (SSH bastion) or "udp" for a
// datagram transport (WireGuard endpoint). For "udp" the returned conn
// carries length-prefixed datagrams: write one whole packet per Write,
// read one whole packet per Read (the SDK frames them on the wire; see
// PacketConnOverStream for a net.PacketConn view).
type TunnelVia struct {
	handle string
}

func newTunnelVia(handle string) *TunnelVia {
	if handle == "" {
		return nil
	}
	return &TunnelVia{handle: handle}
}

// Dial opens one connection through the parent tunnel. The returned conn
// is a byte stream; for network="udp" it carries length-prefixed
// datagrams (use PacketConnOverStream to get a net.PacketConn).
func (v *TunnelVia) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	cli, err := hostTunnelClient()
	if err != nil {
		return nil, err
	}
	stream, err := cli.DialVia(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Init{Init: &pb.DialInit{
		TunnelHandle: v.handle,
		Network:      network,
		Addr:         addr,
	}}}); err != nil {
		return nil, err
	}
	return &viaConn{stream: stream, addr: addr}, nil
}

func hostTunnelClient() (pb.HostTunnelClient, error) {
	c, err := hostServicesConn()
	if err != nil {
		return nil, err
	}
	return pb.NewHostTunnelClient(c), nil
}

// viaConn wraps a HostTunnel.DialVia bidi stream as a net.Conn (the
// client-side mirror of the gateway's dialConn).
type viaConn struct {
	stream pb.HostTunnel_DialViaClient
	addr   string

	mu      sync.Mutex
	readBuf []byte
	closed  bool
	wMu     sync.Mutex
	once    sync.Once
}

func (c *viaConn) Read(p []byte) (int, error) {
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

func (c *viaConn) Write(p []byte) (int, error) {
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

func (c *viaConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		_ = c.stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Close{Close: &pb.DialClose{}}})
		_ = c.stream.CloseSend()
	})
	return nil
}

func (c *viaConn) LocalAddr() net.Addr                { return viaAddr("via") }
func (c *viaConn) RemoteAddr() net.Addr               { return viaAddr(c.addr) }
func (c *viaConn) SetDeadline(_ time.Time) error      { return nil }
func (c *viaConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *viaConn) SetWriteDeadline(_ time.Time) error { return nil }

type viaAddr string

func (a viaAddr) Network() string { return "plugin-tunnel-via" }
func (a viaAddr) String() string  { return string(a) }
