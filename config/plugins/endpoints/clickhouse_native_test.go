package endpoints

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestChVarUInt exercises the LEB128 varint helpers across the byte
// boundaries that matter on the wire (single-byte, two-byte rollover,
// the protocol-revision range that real ClickHouse clients land in).
func TestChVarUInt(t *testing.T) {
	cases := []int{0, 1, 0x7f, 0x80, 0x3fff, 54448 /* recent CH revision */, 1 << 28}
	for _, v := range cases {
		buf := appendChVarUInt(nil, v)
		got, n, err := readChVarUInt(buf, 0)
		if err != nil {
			t.Fatalf("readChVarUInt(%d): %v", v, err)
		}
		if got != v {
			t.Errorf("varuint roundtrip: got %d, want %d (bytes=%v)", got, v, buf)
		}
		if n != len(buf) {
			t.Errorf("varuint(%d) consumed %d bytes, want %d", v, n, len(buf))
		}
	}
}

func TestChVarUIntShortBuffer(t *testing.T) {
	// 0x80 alone signals "more bytes follow" but there are none.
	if _, _, err := readChVarUInt([]byte{0x80}, 0); err != errChShortBuffer {
		t.Fatalf("readChVarUInt(short): err = %v, want errChShortBuffer", err)
	}
}

// TestChHelloRoundtrip verifies that parse(serialize(h)) == h for a
// representative client Hello.
func TestChHelloRoundtrip(t *testing.T) {
	h := ChHello{
		PacketType:       0,
		ClientName:       "ClickHouse client",
		VersionMajor:     24,
		VersionMinor:     8,
		ProtocolRevision: 54448,
		Database:         "analytics",
		Username:         "alice",
		Password:         "hunter2",
	}
	wire := SerializeChHello(h)
	got, n, err := ParseChHello(wire)
	if err != nil {
		t.Fatalf("ParseChHello: %v", err)
	}
	if n != len(wire) {
		t.Errorf("ParseChHello consumed %d, want %d", n, len(wire))
	}
	if diff := cmp.Diff(h, got); diff != "" {
		t.Errorf("hello mismatch (-want +got):\n%s", diff)
	}
}

// TestChHelloPlaceholderInjection mirrors the gateway's rewrite path:
// parse → swap username/password → serialize. The rewritten bytes
// must (a) decode back to the new fields and (b) preserve every other
// field byte-for-byte so the upstream sees the agent's exact client
// metadata.
func TestChHelloPlaceholderInjection(t *testing.T) {
	original := ChHello{
		PacketType:       0,
		ClientName:       "agent-cli",
		VersionMajor:     1,
		VersionMinor:     0,
		ProtocolRevision: 54448,
		Database:         "default",
		Username:         "CLAWPATROL_PH_user",
		Password:         "CLAWPATROL_PH_pass",
	}
	wire := SerializeChHello(original)

	parsed, _, err := ParseChHello(wire)
	if err != nil {
		t.Fatalf("ParseChHello: %v", err)
	}
	parsed.Username = "real-user"
	parsed.Password = "real-pass"
	rewritten := SerializeChHello(parsed)

	final, _, err := ParseChHello(rewritten)
	if err != nil {
		t.Fatalf("ParseChHello rewritten: %v", err)
	}
	if final.Username != "real-user" || final.Password != "real-pass" {
		t.Errorf("injection failed: got user=%q pass=%q", final.Username, final.Password)
	}
	// Non-credential fields untouched.
	if final.ClientName != original.ClientName ||
		final.Database != original.Database ||
		final.VersionMajor != original.VersionMajor ||
		final.ProtocolRevision != original.ProtocolRevision {
		t.Errorf("non-credential fields drifted: %+v vs %+v", final, original)
	}
}

// TestChHelloShortBuffer drives the incremental-parse contract
// HandleConn relies on: when the buffer ends mid-packet, the parser
// returns errChShortBuffer so the caller can read more bytes.
func TestChHelloShortBuffer(t *testing.T) {
	wire := SerializeChHello(ChHello{
		PacketType:       0,
		ClientName:       "ClickHouse client",
		VersionMajor:     24,
		VersionMinor:     8,
		ProtocolRevision: 54448,
		Database:         "analytics",
		Username:         "alice",
		Password:         "hunter2",
	})
	for cut := 0; cut < len(wire); cut++ {
		_, _, err := ParseChHello(wire[:cut])
		if err != errChShortBuffer {
			t.Errorf("ParseChHello(prefix len=%d): err = %v, want errChShortBuffer", cut, err)
		}
	}
}

// TestChHelloRejectsNonHello asserts that the parser refuses packets
// whose first VarUInt isn't 0 (Hello). Important because the runtime
// dispatches off the result and we don't want a Query packet to be
// silently treated as a Hello.
func TestChHelloRejectsNonHello(t *testing.T) {
	bad := appendChVarUInt(nil, 1) // packet type 1 = Query
	bad = appendChString(bad, "x")
	if _, _, err := ParseChHello(bad); err == nil {
		t.Errorf("ParseChHello accepted non-Hello packet")
	}
}

// TestChHelloPreservesTrailing confirms post-password bytes (addendum
// data, inline pipelined packets) survive a parse + serialize cycle
// when reattached.
func TestChHelloPreservesTrailing(t *testing.T) {
	h := ChHello{
		PacketType:       0,
		ClientName:       "c",
		VersionMajor:     1,
		VersionMinor:     0,
		ProtocolRevision: 54448,
		Database:         "d",
		Username:         "u",
		Password:         "p",
		Trailing:         []byte{0xde, 0xad, 0xbe, 0xef},
	}
	wire := SerializeChHello(h)
	parsed, consumed, err := ParseChHello(wire)
	if err != nil {
		t.Fatalf("ParseChHello: %v", err)
	}
	if !bytes.Equal(wire[consumed:], h.Trailing) {
		t.Errorf("trailing bytes lost: got %x, want %x", wire[consumed:], h.Trailing)
	}
	parsed.Trailing = wire[consumed:]
	if !bytes.Equal(SerializeChHello(parsed), wire) {
		t.Errorf("serialize(parse(wire)) != wire")
	}
}
