package pluginsdk

import (
	"io"
	"net"
	"sync"
	"time"
)

// streamConn adapts a duplex byte channel (a gRPC bidi stream's
// data frames in our case) to a net.Conn so plugin code can use
// idiomatic Go networking primitives — bufio readers, http.ReadRequest,
// tls.Server, etc. — without learning a stream-RPC API.
//
// It is bidirectional but not half-closable: closing either side
// signals the peer's read goroutine to stop. Deadlines are accepted
// but only enforce on Read (since Write is buffered to a channel
// the peer drains).
type streamConn struct {
	// recv yields bytes the peer sent toward us. The caller closes
	// recv when the peer hangs up.
	recv <-chan []byte
	// send carries bytes we want to ship to the peer. The caller's
	// goroutine drains it and forwards over the underlying transport.
	send chan<- []byte
	// closeFn tears down both directions. Idempotent.
	closeFn func()

	mu      sync.Mutex
	closed  bool
	readBuf []byte

	rdMu       sync.Mutex
	rdDeadline time.Time

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newStreamConn(recv <-chan []byte, send chan<- []byte, closeFn func(), local, remote net.Addr) *streamConn {
	return &streamConn{
		recv:       recv,
		send:       send,
		closeFn:    closeFn,
		localAddr:  local,
		remoteAddr: remote,
	}
}

// Read drains buffered bytes first, then blocks on the next frame.
// io.EOF is returned when the recv channel closes cleanly.
func (c *streamConn) Read(p []byte) (int, error) {
	c.rdMu.Lock()
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.rdMu.Unlock()
		return n, nil
	}
	deadline := c.rdDeadline
	c.rdMu.Unlock()

	var (
		next []byte
		ok   bool
	)
	if deadline.IsZero() {
		next, ok = <-c.recv
	} else {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, errReadTimeout
		}
		t := time.NewTimer(d)
		select {
		case next, ok = <-c.recv:
			t.Stop()
		case <-t.C:
			return 0, errReadTimeout
		}
	}
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, next)
	if n < len(next) {
		c.rdMu.Lock()
		c.readBuf = append(c.readBuf, next[n:]...)
		c.rdMu.Unlock()
	}
	return n, nil
}

// Write ships p to the peer. Returns io.ErrClosedPipe after Close.
func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()
	// Copy because the gRPC layer holds the slice asynchronously.
	buf := append([]byte(nil), p...)
	c.send <- buf
	return len(p), nil
}

// Close tears down both directions. Safe to call multiple times.
func (c *streamConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	if c.closeFn != nil {
		c.closeFn()
	}
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *streamConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *streamConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.rdMu.Lock()
	c.rdDeadline = t
	c.rdMu.Unlock()
	return nil
}

func (c *streamConn) SetWriteDeadline(_ time.Time) error {
	// Write is bounded only by the send channel's drain rate, which
	// the SDK keeps unbuffered + actively pumped. No timer needed for
	// the protocols the v1 example exercises.
	return nil
}

// fakeAddr is used for LocalAddr / RemoteAddr on stream-backed conns;
// callers that care about the real peer should look at Conn.PeerIP.
type fakeAddr struct{ name string }

func (a fakeAddr) Network() string { return "plugin" }
func (a fakeAddr) String() string  { return a.name }

var errReadTimeout = errReadDeadline{}

type errReadDeadline struct{}

func (errReadDeadline) Error() string   { return "read deadline exceeded" }
func (errReadDeadline) Timeout() bool   { return true }
func (errReadDeadline) Temporary() bool { return true }
