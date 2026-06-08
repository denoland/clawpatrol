//go:build linux

package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestRunUDPForwarderCleansIdleFlowAfterReadTimeout(t *testing.T) {
	oldTimeout := runUDPFlowIdleTimeout
	runUDPFlowIdleTimeout = 10 * time.Millisecond
	t.Cleanup(func() { runUDPFlowIdleTimeout = oldTimeout })

	transport := &cleanupTestTransport{conn: newCleanupTestConn()}
	f := &runUDPForwarder{
		transport: transport,
		flows:     map[udpFlowKey]net.Conn{},
	}
	pkt := buildUDPPacket([4]byte{100, 98, 20, 53}, [4]byte{192, 0, 2, 10}, 53000, 9999, []byte("ping"))
	f.handle(pkt)

	if got := transport.conn.writes(); got != 1 {
		t.Fatalf("transport writes = %d, want 1", got)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		flows := len(f.flows)
		f.mu.Unlock()
		if flows == 0 {
			if !transport.conn.closed() {
				t.Fatal("flow was removed before conn closed")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.mu.Lock()
	flows := len(f.flows)
	f.mu.Unlock()
	t.Fatalf("flow count = %d after timeout, want 0", flows)
}

type cleanupTestTransport struct{ conn *cleanupTestConn }

func (t *cleanupTestTransport) Dial(context.Context, string, string) (net.Conn, error) {
	return t.conn, nil
}
func (t *cleanupTestTransport) LocalAddr() netip.Addr {
	return netip.MustParseAddr("100.98.20.53")
}

func (t *cleanupTestTransport) BootWarning() string {
	return ""
}

func (t *cleanupTestTransport) Close() error {
	return nil
}

type cleanupTestConn struct {
	mu       sync.Mutex
	deadline time.Time
	writeN   int
	closedV  bool
}

func newCleanupTestConn() *cleanupTestConn {
	return &cleanupTestConn{}
}

func (c *cleanupTestConn) Read([]byte) (int, error) {
	for {
		c.mu.Lock()
		deadline := c.deadline
		closed := c.closedV
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return 0, timeoutErr{}
		}
		time.Sleep(time.Millisecond)
	}
}

func (c *cleanupTestConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedV {
		return 0, net.ErrClosed
	}
	c.writeN++
	return len(b), nil
}

func (c *cleanupTestConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closedV = true
	return nil
}
func (c *cleanupTestConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.98.20.53:53000"))
}

func (c *cleanupTestConn) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.10:9999"))
}

func (c *cleanupTestConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return nil
}

func (c *cleanupTestConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *cleanupTestConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}
func (c *cleanupTestConn) writes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeN
}
func (c *cleanupTestConn) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closedV
}

type timeoutErr struct{}

func (timeoutErr) Error() string {
	return "i/o timeout"
}

func (timeoutErr) Timeout() bool {
	return true
}

func (timeoutErr) Temporary() bool {
	return true
}

var _ net.Error = timeoutErr{}
