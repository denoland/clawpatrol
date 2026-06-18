package pluginsdk

import (
	"bytes"
	"net"
	"testing"
)

// Datagram framing must round-trip exactly — both the WireGuard plugin
// (writes/reads packets over its `via` conduit) and the SOCKS plugin
// (reframes them onto a UDP relay) depend on this byte-for-byte.
func TestDatagramRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	packets := [][]byte{
		[]byte("first"),
		{},                               // empty datagram
		bytes.Repeat([]byte{0xab}, 1500), // jumbo-ish
		[]byte("last"),
	}
	for _, p := range packets {
		if err := WriteDatagram(&buf, p); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for i, want := range packets {
		got, err := ReadDatagram(&buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("datagram %d = %q, want %q", i, got, want)
		}
	}
}

// PacketConnOverStream presents the framed stream as a connected
// net.PacketConn (what the WG plugin wraps its via conduit in).
func TestPacketConnOverStream(t *testing.T) {
	a, b := net.Pipe()
	remote := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 51820}
	pcA := PacketConnOverStream(a, remote)
	pcB := PacketConnOverStream(b, remote)

	want := []byte("wireguard handshake bytes")
	go func() { _, _ = pcA.WriteTo(want, remote) }()

	buf := make([]byte, 1500)
	n, addr, err := pcB.ReadFrom(buf)
	if err != nil {
		t.Fatalf("readfrom: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %q, want %q", buf[:n], want)
	}
	if addr.String() != remote.String() {
		t.Fatalf("addr = %s, want %s", addr, remote)
	}
}
