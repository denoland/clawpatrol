package pluginsdk

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// Datagram framing for carrying UDP packets over a byte stream (a `via`
// conduit through a parent tunnel). Each datagram is a 2-byte big-endian
// length followed by that many payload bytes. Both ends of a chained
// udp-via must use this framing: the child (e.g. WireGuard) writes/reads
// packets, and the parent (e.g. a SOCKS plugin) reframes them onto a real
// datagram transport. 16-bit length caps a datagram at 65535 bytes, which
// covers any UDP payload.

const maxDatagram = 0xffff

// WriteDatagram writes one length-prefixed datagram to w.
func WriteDatagram(w io.Writer, p []byte) error {
	if len(p) > maxDatagram {
		p = p[:maxDatagram]
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

// ReadDatagram reads one length-prefixed datagram from r.
func ReadDatagram(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// PacketConnOverStream presents a byte stream carrying length-prefixed
// datagrams (see WriteDatagram/ReadDatagram) as a connected
// net.PacketConn. The remote address is fixed (the stream already routes
// to one endpoint), so the addr argument to WriteTo is ignored and
// ReadFrom always reports remote. This is what a WireGuard plugin wraps
// its `via` conduit in so wireguard-go's bind can speak datagrams over a
// chained tunnel.
func PacketConnOverStream(conn net.Conn, remote net.Addr) net.PacketConn {
	return &packetConnOverStream{conn: conn, remote: remote}
}

type packetConnOverStream struct {
	conn   net.Conn
	remote net.Addr
	rMu    sync.Mutex
	wMu    sync.Mutex
}

func (p *packetConnOverStream) ReadFrom(b []byte) (int, net.Addr, error) {
	p.rMu.Lock()
	defer p.rMu.Unlock()
	d, err := ReadDatagram(p.conn)
	if err != nil {
		return 0, nil, err
	}
	return copy(b, d), p.remote, nil
}

func (p *packetConnOverStream) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.wMu.Lock()
	defer p.wMu.Unlock()
	if err := WriteDatagram(p.conn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetConnOverStream) Close() error                       { return p.conn.Close() }
func (p *packetConnOverStream) LocalAddr() net.Addr                { return p.conn.LocalAddr() }
func (p *packetConnOverStream) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *packetConnOverStream) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *packetConnOverStream) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }
