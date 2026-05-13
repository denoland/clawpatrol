package extplugin

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	pb "github.com/denoland/clawpatrol/config/extplugin/proto"
)

// dialConn wraps a Tunnel.Dial bidi gRPC stream as a net.Conn so the
// gateway's existing transports (http.Transport, postgres MITM,
// kubectl client, ...) can use it as if it were a plain TCP socket.
type dialConn struct {
	stream pb.Tunnel_DialClient
	addr   string

	mu       sync.Mutex
	closed   bool
	readBuf  []byte
	closeErr error
	once     sync.Once

	wMu sync.Mutex
}

func newDialConn(stream pb.Tunnel_DialClient, addr string) *dialConn {
	return &dialConn{stream: stream, addr: addr}
}

func (c *dialConn) Read(p []byte) (int, error) {
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

func (c *dialConn) Write(p []byte) (int, error) {
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

func (c *dialConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		_ = c.stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Close{Close: &pb.DialClose{}}})
		c.closeErr = c.stream.CloseSend()
	})
	return c.closeErr
}

func (c *dialConn) LocalAddr() net.Addr  { return tunnelAddr{name: "tunnel"} }
func (c *dialConn) RemoteAddr() net.Addr { return tunnelAddr{name: c.addr} }

func (c *dialConn) SetDeadline(_ time.Time) error      { return nil }
func (c *dialConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *dialConn) SetWriteDeadline(_ time.Time) error { return nil }

type tunnelAddr struct{ name string }

func (a tunnelAddr) Network() string { return "plugin-tunnel" }
func (a tunnelAddr) String() string  { return a.name }
