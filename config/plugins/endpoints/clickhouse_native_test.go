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
	cases := []uint64{0, 1, 0x7f, 0x80, 0x3fff, 54448 /* recent CH revision */, 1 << 28, 1 << 50, ^uint64(0)}
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

// TestChHelloRejectsInvalidUTF8 confirms that the string reader
// refuses non-UTF-8 bytes inside a length-prefixed string. Defends
// the per-session log + ConnEvent surface against arbitrary-byte
// peers.
func TestChHelloRejectsInvalidUTF8(t *testing.T) {
	// Build a Hello where client_name carries a stray 0xff (invalid
	// UTF-8 lead byte). Hand-craft the wire bytes — the serializer
	// won't produce these from a string.
	var wire []byte
	wire = appendChVarUInt(wire, 0)        // packet type Hello
	wire = appendChVarUInt(wire, 1)        // client_name length
	wire = append(wire, 0xff)              // invalid UTF-8 byte
	wire = appendChVarUInt(wire, 1)        // major
	wire = appendChVarUInt(wire, 0)        // minor
	wire = appendChVarUInt(wire, 54448)    // revision
	wire = appendChString(wire, "default") // database
	wire = appendChString(wire, "u")       // user
	wire = appendChString(wire, "p")       // password
	if _, _, err := ParseChHello(wire); err == nil {
		t.Errorf("ParseChHello accepted invalid UTF-8 in client_name")
	}
}

// TestClickhouseConnRouteHostsNoDoublePort verifies the
// host-port-already-present branch: if an operator binds a host as
// "ch.example.com:9000", ConnRouteHosts must preserve it verbatim
// rather than producing "ch.example.com:9000:9000".
func TestClickhouseConnRouteHostsNoDoublePort(t *testing.T) {
	e := &ClickhouseNativeEndpoint{
		Hosts: []string{
			"bare.example.com",
			"with-port.example.com:9001",
			"[::1]:9002",
		},
		Port: 9000,
	}
	got := e.ConnRouteHosts()
	want := []string{
		"bare.example.com:9000",
		"with-port.example.com:9001",
		"[::1]:9002",
	}
	if len(got) != len(want) {
		t.Fatalf("ConnRouteHosts: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ConnRouteHosts[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestClickhouseDefaultPortTLS pins the default-port fork: when the
// operator omits Port, plaintext endpoints land on 9000 and TLS
// endpoints on 9440 (ClickHouse's published convention). An explicit
// Port always wins over the TLS-derived default.
func TestClickhouseDefaultPortTLS(t *testing.T) {
	cases := []struct {
		name string
		e    ClickhouseNativeEndpoint
		want string
	}{
		{
			name: "no port, plaintext → 9000",
			e:    ClickhouseNativeEndpoint{Hosts: []string{"ch.example.com"}},
			want: "ch.example.com:9000",
		},
		{
			name: "no port, tls → 9440",
			e:    ClickhouseNativeEndpoint{Hosts: []string{"ch.example.com"}, TLS: true},
			want: "ch.example.com:9440",
		},
		{
			name: "explicit port wins over tls default",
			e:    ClickhouseNativeEndpoint{Hosts: []string{"ch.example.com"}, TLS: true, Port: 9001},
			want: "ch.example.com:9001",
		},
	}
	for _, c := range cases {
		got := c.e.EndpointHosts()
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: EndpointHosts() = %v, want [%q]", c.name, got, c.want)
		}
	}
}

// TestChHostPort exercises the host:port splitter — including the
// IPv6 + named-port edge cases that strconv.Atoi covers but the
// hand-rolled digit walk did not.
func TestChHostPort(t *testing.T) {
	cases := []struct {
		addr     string
		wantHost string
		wantPort int
	}{
		{"host:9000", "host", 9000},
		{"[::1]:9000", "::1", 9000},
		{"host:not-a-port", "host", 0},
		{"no-colon", "no-colon", 0},
	}
	for _, c := range cases {
		h, p := chHostPort(c.addr)
		if h != c.wantHost || p != c.wantPort {
			t.Errorf("chHostPort(%q) = (%q,%d), want (%q,%d)",
				c.addr, h, p, c.wantHost, c.wantPort)
		}
	}
}

// TestClickhouseRequiresVIP nails down the marker — clickhouse_native
// always opts into VIP allocation. The dispatcher's IP-literal carve-
// out happens at the dnsvip layer (entries whose host is an IP are
// skipped during VIP allocation), not by toggling RequiresVIP per
// host, so the plugin can return a constant true.
func TestClickhouseRequiresVIP(t *testing.T) {
	e := &ClickhouseNativeEndpoint{}
	if !e.RequiresVIP() {
		t.Fatal("ClickhouseNativeEndpoint.RequiresVIP() = false, want true")
	}
}

// TestClickhousePickUpstream covers the upstream-resolver helper
// across the dispatch shapes the plugin has to handle: VIP path
// (UpstreamHost + DstPort known), direct-IP fallback (only DstPort),
// and the legacy first-host fallback when both are missing. Multi-
// host / mixed-port endpoints rely on DstPort matching to disambiguate.
func TestClickhousePickUpstream(t *testing.T) {
	cases := []struct {
		name         string
		hosts        []string
		upstreamHost string
		dstPort      uint16
		defaultPort  int
		want         string
	}{
		{
			name:         "vip path: hostname + port supplied",
			hosts:        []string{"a.example.com:9440", "b.example.com:9440"},
			upstreamHost: "b.example.com",
			dstPort:      9440,
			defaultPort:  9000,
			want:         "b.example.com:9440",
		},
		{
			name:        "direct-ip path: only dst port → port-matched first host",
			hosts:       []string{"172.17.0.1:19440", "192.168.1.5:9000"},
			dstPort:     9000,
			defaultPort: 9000,
			want:        "192.168.1.5:9000",
		},
		{
			name:        "fallback: no upstream/port → first host",
			hosts:       []string{"only.example.com:9000"},
			defaultPort: 9000,
			want:        "only.example.com:9000",
		},
		{
			name:        "bare hostname falls back to defaultPort",
			hosts:       []string{"bare.example.com"},
			defaultPort: 9000,
			want:        "bare.example.com:9000",
		},
		{
			name:        "no hosts → empty string",
			hosts:       nil,
			defaultPort: 9000,
			want:        "",
		},
	}
	for _, c := range cases {
		got := chPickUpstream(c.hosts, c.upstreamHost, c.dstPort, c.defaultPort)
		if got != c.want {
			t.Errorf("%s: chPickUpstream(%v, %q, %d, %d) = %q, want %q",
				c.name, c.hosts, c.upstreamHost, c.dstPort, c.defaultPort, got, c.want)
		}
	}
}
