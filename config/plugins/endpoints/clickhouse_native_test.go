package endpoints

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"
)

// chBuildClientInfo writes a representative ClientInfo block for the
// given revision, mirroring the order ClickHouse's
// src/Interpreters/ClientInfo.cpp::write produces. Tests use it to
// hand the parser realistic Query packets without re-implementing
// the field set inline at every call site.
func chBuildClientInfo(rev uint64) []byte {
	var b []byte
	b = append(b, 1) // query_kind = INITIAL_QUERY
	b = appendChString(b, "alice")
	b = appendChString(b, "qid-1")
	b = appendChString(b, "127.0.0.1:0")
	if rev >= chMinRevWithInitialQueryStartTime {
		b = append(b, make([]byte, 8)...) // initial_query_start_time
	}
	b = append(b, byte(chClientInterfaceTCP))
	b = appendChString(b, "alice-os")
	b = appendChString(b, "host")
	b = appendChString(b, "ClickHouse client")
	b = appendChVarUInt(b, 24)
	b = appendChVarUInt(b, 8)
	b = appendChVarUInt(b, rev)
	if rev >= chMinRevWithQuotaKeyInClientInfo {
		b = appendChString(b, "")
	}
	if rev >= chMinRevWithDistributedDepth {
		b = appendChVarUInt(b, 0)
	}
	if rev >= chMinRevWithVersionPatch {
		b = appendChVarUInt(b, 0)
	}
	if rev >= chMinRevWithOpenTelemetry {
		b = append(b, 0) // trace_present = 0
	}
	if rev >= chMinRevWithParallelReplicas {
		b = appendChVarUInt(b, 0)
		b = appendChVarUInt(b, 0)
		b = appendChVarUInt(b, 0)
	}
	return b
}

// chBuildQuery builds a complete client Query packet for the given
// revision: header + ClientInfo + (empty) settings + (optional)
// interserver secret + stage + compression + sql + (optional) empty
// parameters.
func chBuildQuery(rev uint64, sql string) []byte {
	var b []byte
	b = appendChVarUInt(b, chClientPacketQuery)
	b = appendChString(b, "qid-1")
	if rev >= chMinRevWithClientInfo {
		b = append(b, chBuildClientInfo(rev)...)
	}
	// Settings — empty: just the terminator empty key.
	b = appendChString(b, "")
	if rev >= chMinRevWithInterserverSecret {
		b = appendChString(b, "")
	}
	b = appendChVarUInt(b, 2) // stage = Complete
	b = appendChVarUInt(b, 0) // compression = Disable
	b = appendChString(b, sql)
	if rev >= chMinRevWithParameters {
		b = appendChString(b, "")
	}
	return b
}

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

// TestClickhouseUpstreamTLSConfig pins the AcceptInvalidCertificate
// → InsecureSkipVerify mapping that gates the self-signed-CA opt-out.
func TestClickhouseUpstreamTLSConfig(t *testing.T) {
	cases := []struct {
		name              string
		acceptInvalidCert bool
		wantSkip          bool
		wantSrvName       string
	}{
		{"default verifies", false, false, "ch.example.com"},
		{"accept_invalid skips verification", true, true, "ch.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := chUpstreamTLSConfig("ch.example.com", c.acceptInvalidCert)
			if cfg.InsecureSkipVerify != c.wantSkip {
				t.Errorf("acceptInvalidCert=%v InsecureSkipVerify=%v, want %v",
					c.acceptInvalidCert, cfg.InsecureSkipVerify, c.wantSkip)
			}
			if cfg.ServerName != c.wantSrvName {
				t.Errorf("acceptInvalidCert=%v ServerName=%q, want %q",
					c.acceptInvalidCert, cfg.ServerName, c.wantSrvName)
			}
		})
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

// TestParseChQueryRevisions exercises the Query packet parser across
// the revisions modern ClickHouse clients negotiate. The parser must
// extract the SQL string regardless of which OpenTelemetry / parallel-
// replicas / parameters fields are present — these toggle on at fixed
// rev gates and shift every subsequent field's offset.
func TestParseChQueryRevisions(t *testing.T) {
	const sample = "SELECT id FROM users WHERE id = 1"
	for _, rev := range []uint64{
		chMinRevWithSettingsAsStrings,     // 54429: lower bound we support
		chMinRevWithInterserverSecret,     // 54441
		chMinRevWithOpenTelemetry,         // 54442
		chMinRevWithParallelReplicas,      // 54447
		chMinRevWithDistributedDepth,      // 54448
		chMinRevWithInitialQueryStartTime, // 54449
		chMinRevWithParameters,            // 54459
		54470,                             // beyond known gates: parser must still find the SQL
	} {
		buf := chBuildQuery(rev, sample)
		view, err := ParseChQuery(buf, rev)
		if err != nil {
			t.Fatalf("rev %d: ParseChQuery: %v", rev, err)
		}
		if view.SQL != sample {
			t.Errorf("rev %d: SQL = %q, want %q", rev, view.SQL, sample)
		}
		if view.End != len(buf) {
			t.Errorf("rev %d: End = %d, want %d", rev, view.End, len(buf))
		}
	}
}

// TestParseChQueryShortBuffer drives the incremental-parse contract
// the runtime relies on: the parser must signal errChShortBuffer at
// every byte boundary so the read loop can pull more bytes and retry.
func TestParseChQueryShortBuffer(t *testing.T) {
	rev := uint64(chMinRevWithParameters)
	buf := chBuildQuery(rev, "SELECT 1")
	for cut := 0; cut < len(buf); cut++ {
		_, err := ParseChQuery(buf[:cut], rev)
		if err != errChShortBuffer {
			t.Errorf("ParseChQuery(prefix=%d): err = %v, want errChShortBuffer", cut, err)
		}
	}
}

// TestParseChQueryRejectsLowRevision pins the lower-bound gate: pre-
// 21.x clients (rev < chMinRevWithSettingsAsStrings) use a
// type-prefixed BINARY settings format the parser doesn't implement.
// The error lets the runtime fall back to verbatim forwarding.
func TestParseChQueryRejectsLowRevision(t *testing.T) {
	if _, err := ParseChQuery([]byte{0x01}, chMinRevWithSettingsAsStrings-1); err == errChShortBuffer || err == nil {
		t.Fatalf("ParseChQuery(low rev): err = %v, want non-short-buffer error", err)
	}
}

// TestParseChQueryRejectsNonQuery confirms the parser refuses non-
// Query packets — important for the runtime's "first client packet"
// branch where a Cancel or Ping must take the verbatim path.
func TestParseChQueryRejectsNonQuery(t *testing.T) {
	buf := appendChVarUInt(nil, chClientPacketCancel)
	if _, err := ParseChQuery(buf, chMinRevWithParameters); err == nil {
		t.Errorf("ParseChQuery accepted non-Query packet")
	}
}

// TestParseChServerHelloRevision pulls just the negotiated revision
// out of a server Hello — the runtime forwards the full bytes
// verbatim, this helper exists to gate Query-packet parsing on the
// negotiated revision.
func TestParseChServerHelloRevision(t *testing.T) {
	want := uint64(54470)
	var buf []byte
	buf = appendChVarUInt(buf, chServerPacketHello)
	buf = appendChString(buf, "ClickHouse")
	buf = appendChVarUInt(buf, 24)
	buf = appendChVarUInt(buf, 8)
	buf = appendChVarUInt(buf, want)
	buf = appendChString(buf, "Etc/UTC")
	got, err := ParseChServerHelloRevision(buf)
	if err != nil {
		t.Fatalf("ParseChServerHelloRevision: %v", err)
	}
	if got != want {
		t.Errorf("revision = %d, want %d", got, want)
	}
}

// TestParseChServerHelloRevisionRejectsException covers the pre-Hello
// upstream-error path: a misconfigured server can reply with an
// Exception packet where we expected a Hello. The runtime needs a
// distinct error so it doesn't silently mistake server bytes for a
// Hello.
func TestParseChServerHelloRevisionRejectsException(t *testing.T) {
	buf := appendChVarUInt(nil, chServerPacketException)
	if _, err := ParseChServerHelloRevision(buf); err == nil {
		t.Errorf("ParseChServerHelloRevision accepted Exception packet")
	}
}

// TestParseChSQL covers the matcher-input lexer's coverage of the v14
// rule shapes: verb extraction, table refs across FROM/JOIN/INTO,
// stripping ClickHouse trailers (FORMAT, SETTINGS) before regex
// extraction, and comment handling.
func TestParseChSQL(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want chSQLInfo
	}{
		{
			"select with format trailer",
			"SELECT id FROM users FORMAT JSON",
			chSQLInfo{
				Verb:      "select",
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "SELECT id FROM users FORMAT JSON",
			},
		},
		{
			"insert with settings trailer",
			"INSERT INTO events (ts, body) VALUES (now(), 'x') SETTINGS max_insert_threads = 4",
			chSQLInfo{
				Verb:      "insert",
				Tables:    []string{"events"},
				Functions: []string{"events", "values", "now"},
				Statement: "INSERT INTO events (ts, body) VALUES (now(), 'x') SETTINGS max_insert_threads = 4",
			},
		},
		{
			"line comments stripped",
			"-- audit\nSELECT id FROM secrets",
			chSQLInfo{
				Verb:      "select",
				Tables:    []string{"secrets"},
				Functions: nil,
				Statement: "-- audit\nSELECT id FROM secrets",
			},
		},
		{
			"block comments stripped",
			"/* note */ SELECT count() FROM events",
			chSQLInfo{
				Verb:      "select",
				Tables:    []string{"events"},
				Functions: []string{"count"},
				Statement: "/* note */ SELECT count() FROM events",
			},
		},
		{
			"join extracts both tables",
			"SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			chSQLInfo{
				Verb:      "select",
				Tables:    []string{"users", "tokens"},
				Functions: nil,
				Statement: "SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			},
		},
		{
			"empty sql preserved",
			"",
			chSQLInfo{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseChSQL(tc.sql)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseChSQL mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSerializeChException pins the Exception-packet wire format the
// runtime emits on policy deny. ClickHouse client renders the
// display_text — we assert the leading varuint type, error code,
// and string offsets are recoverable so the agent can read the
// reason out cleanly.
func TestSerializeChException(t *testing.T) {
	out := SerializeChException(497, "denied by policy")

	// type
	pkt, n, err := readChVarUInt(out, 0)
	if err != nil {
		t.Fatalf("readChVarUInt: %v", err)
	}
	if pkt != chServerPacketException {
		t.Errorf("packet type = %d, want %d", pkt, chServerPacketException)
	}
	off := n

	// 4-byte LE error code
	if off+4 > len(out) {
		t.Fatalf("buffer too short for error code")
	}
	got := uint32(out[off]) | uint32(out[off+1])<<8 | uint32(out[off+2])<<16 | uint32(out[off+3])<<24
	if got != 497 {
		t.Errorf("error code = %d, want 497", got)
	}
	off += 4

	name, n, err := readChString(out, off)
	if err != nil || name != "DB::Exception" {
		t.Errorf("name = %q err=%v, want DB::Exception", name, err)
	}
	off += n
	display, n, err := readChString(out, off)
	if err != nil || display != "denied by policy" {
		t.Errorf("display = %q err=%v, want %q", display, err, "denied by policy")
	}
	off += n
	stack, n, err := readChString(out, off)
	if err != nil || stack != "" {
		t.Errorf("stack = %q err=%v, want empty", stack, err)
	}
	off += n
	if off != len(out)-1 {
		t.Errorf("trailing has_nested byte at wrong offset (off=%d len=%d)", off, len(out))
	}
	if out[len(out)-1] != 0 {
		t.Errorf("has_nested byte = %d, want 0", out[len(out)-1])
	}
}

// chBuildEndpoint hand-builds a *CompiledEndpoint with a list of
// pre-compiled rules. Tests use it to exercise the policy pipeline
// without spinning up the full HCL → Build → Compile path — the
// matcher's input shape is what we care about, not how the policy
// got there.
func chBuildEndpoint(t *testing.T, rules ...*config.CompiledRule) *config.CompiledEndpoint {
	t.Helper()
	return &config.CompiledEndpoint{
		Name:   "test-ch",
		Family: "sql",
		Body:   &ClickhouseNativeEndpoint{Hosts: []string{"ch.example:9000"}},
		Hosts:  []string{"ch.example:9000"},
		Rules:  rules,
	}
}

func chRuleSQL(t *testing.T, name string, raw map[string]any, verdict, reason string, priority int) *config.CompiledRule {
	t.Helper()
	m, err := match.New("sql", raw)
	if err != nil {
		t.Fatalf("compile rule %q: %v", name, err)
	}
	return &config.CompiledRule{
		Name: name, Priority: priority, Match: raw, Matcher: m,
		Outcome: config.Outcome{Verdict: verdict, Reason: reason},
	}
}

// chMockHandle wires a *runtime.ConnHandle around the agent end of an
// in-memory net.Pipe so the inspector's Conn.Write (Exception
// synthesis) hits a buffer the test can read.
type chMockHandle struct {
	*runtime.ConnHandle
	events []runtime.ConnEvent
}

func chNewMockHandle(t *testing.T, ep *config.CompiledEndpoint) (*chMockHandle, net.Conn) {
	t.Helper()
	agentSide, runtimeSide := net.Pipe()
	mock := &chMockHandle{}
	mock.ConnHandle = &runtime.ConnHandle{
		Conn:     runtimeSide,
		Endpoint: ep,
		PeerIP:   "127.0.0.1",
		Emit: func(ev runtime.ConnEvent) {
			mock.events = append(mock.events, ev)
		},
	}
	return mock, agentSide
}

// TestChEvaluateSQLAllowsSelectDeniesInsert is the iter 2 acceptance
// criterion in test form: a sql_rule with `verb = ["insert"]` /
// `verdict = "deny"` denies an INSERT and lets a SELECT through. The
// matcher input is the same shape the runtime constructs (Verb /
// Tables / Functions / Statement).
func TestChEvaluateSQLAllowsSelectDeniesInsert(t *testing.T) {
	denyInsert := chRuleSQL(t, "deny-insert",
		map[string]any{"verb": []any{"insert"}}, "deny", "writes blocked", 100)
	ep := chBuildEndpoint(t, denyInsert)

	mock, _ := chNewMockHandle(t, ep)

	verdict, reason := chEvaluateSQL(context.Background(), mock.ConnHandle, "INSERT INTO events VALUES (1)", "ch-cred")
	if verdict != "deny" {
		t.Errorf("INSERT verdict = %q, want deny", verdict)
	}
	if reason != "writes blocked" {
		t.Errorf("INSERT reason = %q, want %q", reason, "writes blocked")
	}

	verdict, _ = chEvaluateSQL(context.Background(), mock.ConnHandle, "SELECT 1", "ch-cred")
	if verdict != "" {
		t.Errorf("SELECT verdict = %q, want allow (empty)", verdict)
	}

	if len(mock.events) != 2 {
		t.Fatalf("expected 2 events (deny + allow), got %d", len(mock.events))
	}
	if mock.events[0].Action != "deny" || mock.events[0].Verb != "insert" {
		t.Errorf("first event: %+v", mock.events[0])
	}
	if mock.events[1].Action != "allow" || mock.events[1].Verb != "select" {
		t.Errorf("second event: %+v", mock.events[1])
	}
}

// chMockApprove hands ConnHandle.Approve a deterministic verdict so
// the approve-chain branch can be exercised without spinning up the
// HITL machinery.
func chMockApprove(decision, reason string) func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
	return func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
		return runtime.ApproveVerdict{Decision: decision, Reason: reason, By: "test"}
	}
}

// TestChEvaluateSQLApproveChain covers the third verdict path: rule
// has `approve = [...]`. ConnHandle.Approve runs synchronously; an
// allow lets the query forward, a deny rejects with the approver's
// reason.
func TestChEvaluateSQLApproveChain(t *testing.T) {
	approveRule := &config.CompiledRule{
		Name:  "approve-drops",
		Match: map[string]any{"verb": []any{"drop"}},
		Outcome: config.Outcome{
			Approve: []config.ApproveStage{{Name: "human"}},
		},
	}
	m, err := match.New("sql", approveRule.Match)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	approveRule.Matcher = m
	ep := chBuildEndpoint(t, approveRule)

	t.Run("approver allows", func(t *testing.T) {
		mock, _ := chNewMockHandle(t, ep)
		mock.Approve = chMockApprove("allow", "ok")
		verdict, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred")
		if verdict != "" {
			t.Errorf("approver allow → verdict %q, want empty", verdict)
		}
		if len(mock.events) != 1 || mock.events[0].Action != "hitl_allow" {
			t.Errorf("expected one hitl_allow event, got %+v", mock.events)
		}
	})
	t.Run("approver denies", func(t *testing.T) {
		mock, _ := chNewMockHandle(t, ep)
		mock.Approve = chMockApprove("deny", "operator rejected")
		verdict, reason := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred")
		if verdict != "deny" || reason != "operator rejected" {
			t.Errorf("verdict=%q reason=%q, want deny/operator rejected", verdict, reason)
		}
		if len(mock.events) != 1 || mock.events[0].Action != "hitl_deny" {
			t.Errorf("expected one hitl_deny event, got %+v", mock.events)
		}
	})
	t.Run("missing Approve callback default-denies", func(t *testing.T) {
		mock, _ := chNewMockHandle(t, ep)
		mock.Approve = nil
		verdict, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred")
		if verdict != "deny" {
			t.Errorf("no Approve → verdict %q, want deny", verdict)
		}
	})
}

// TestChMaybeInspectQueryDenyWritesException drives the runtime's
// inspector end-to-end on an in-memory pipe: a Query packet whose
// SQL trips a deny rule must (a) cause the function to signal deny
// and (b) write a server-side Exception packet onto the agent
// connection.
func TestChMaybeInspectQueryDenyWritesException(t *testing.T) {
	rule := chRuleSQL(t, "deny-insert",
		map[string]any{"verb": []any{"insert"}}, "deny", "writes blocked", 100)
	ep := chBuildEndpoint(t, rule)

	mock, agentSide := chNewMockHandle(t, ep)
	defer agentSide.Close()
	defer mock.Conn.Close()

	rev := uint64(chMinRevWithParameters)
	pkt := chBuildQuery(rev, "INSERT INTO events VALUES (1)")

	read := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		_ = agentSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := agentSide.Read(buf)
		read <- append([]byte(nil), buf[:n]...)
	}()

	done, _, deny := chMaybeInspectQuery(context.Background(), mock.ConnHandle, pkt, rev, "ch-cred")
	if !done || !deny {
		t.Fatalf("inspect: done=%v deny=%v, want true/true", done, deny)
	}

	got := <-read
	pktType, _, err := readChVarUInt(got, 0)
	if err != nil {
		t.Fatalf("read exception: %v", err)
	}
	if pktType != chServerPacketException {
		t.Errorf("agent received packet type %d, want Exception(%d)", pktType, chServerPacketException)
	}
}

// TestChMaybeInspectQueryAllowConsumesPacket pins the allow path's
// "consumed = full Query packet length" contract — the runtime
// forwards exactly view.End bytes to upstream and resumes verbatim
// relay from the next byte.
func TestChMaybeInspectQueryAllowConsumesPacket(t *testing.T) {
	rule := chRuleSQL(t, "allow-selects",
		map[string]any{"verb": []any{"select"}}, "allow", "", 100)
	ep := chBuildEndpoint(t, rule)
	mock, agentSide := chNewMockHandle(t, ep)
	defer agentSide.Close()
	defer mock.Conn.Close()

	rev := uint64(chMinRevWithParameters)
	pkt := chBuildQuery(rev, "SELECT 1")
	// Append trailing bytes the runtime should NOT consume.
	full := append([]byte{}, pkt...)
	full = append(full, []byte{0xde, 0xad, 0xbe, 0xef}...)

	done, consumed, deny := chMaybeInspectQuery(context.Background(), mock.ConnHandle, full, rev, "ch-cred")
	if !done || deny {
		t.Fatalf("inspect: done=%v deny=%v, want true/false", done, deny)
	}
	if consumed != len(pkt) {
		t.Errorf("consumed=%d, want %d (Query packet length)", consumed, len(pkt))
	}
}

// TestChMaybeInspectQueryShortBuffer covers the parser-needs-more-
// bytes branch: when buf doesn't yet hold a full Query packet, the
// inspector reports done=false so the runtime keeps reading.
func TestChMaybeInspectQueryShortBuffer(t *testing.T) {
	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	rev := uint64(chMinRevWithParameters)
	pkt := chBuildQuery(rev, "SELECT 1")
	done, _, _ := chMaybeInspectQuery(context.Background(), mock.ConnHandle, pkt[:len(pkt)/2], rev, "ch-cred")
	if done {
		t.Errorf("partial Query packet should not be done")
	}
}

// TestChMaybeInspectQueryNonQueryPasses confirms Cancel/Ping/etc.
// short-circuit through verbatim relay rather than denying or
// blocking on a parse miss.
func TestChMaybeInspectQueryNonQueryPasses(t *testing.T) {
	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	pkt := appendChVarUInt(nil, chClientPacketCancel)
	done, consumed, deny := chMaybeInspectQuery(context.Background(), mock.ConnHandle, pkt, chMinRevWithParameters, "ch-cred")
	if !done || deny {
		t.Errorf("Cancel: done=%v deny=%v, want true/false", done, deny)
	}
	if consumed != 0 {
		t.Errorf("Cancel consumed=%d, want 0 (verbatim relay)", consumed)
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
