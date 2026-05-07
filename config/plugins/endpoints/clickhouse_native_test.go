package endpoints

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	chcompress "github.com/ClickHouse/ch-go/compress"
	chgoproto "github.com/ClickHouse/ch-go/proto"
	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	chproto "github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"github.com/google/go-cmp/cmp"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"
)

// chBuildHelloWire produces the byte-for-byte ClientHello packet a
// real client would send. ch-go/proto.ClientHello.Encode already
// emits the leading ClientCodeHello byte, so this is just a wrapper
// around chEncodeHello that exists to flag the asymmetry with
// chReadHello (which expects the caller to consume the code byte
// before invoking ClientHello.Decode).
func chBuildHelloWire(t *testing.T, h ChHello) []byte {
	t.Helper()
	return chEncodeHello(h)
}

// TestChHelloRoundtrip verifies that decode(encode(h)) returns the
// same fields, end-to-end across the gateway's (encode → wire → ch-go
// decode) pipeline.
func TestChHelloRoundtrip(t *testing.T) {
	h := ChHello{
		ClientName:       "ClickHouse client",
		VersionMajor:     24,
		VersionMinor:     8,
		ProtocolRevision: 54448,
		Database:         "analytics",
		Username:         "alice",
		Password:         "hunter2",
	}
	wire := chBuildHelloWire(t, h)

	got, _, err := chReadHello(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("chReadHello: %v", err)
	}
	if diff := cmp.Diff(h, got); diff != "" {
		t.Errorf("hello mismatch (-want +got):\n%s", diff)
	}
}

// TestChHelloPlaceholderInjection mirrors the gateway's rewrite path:
// decode → swap username/password → encode. The rewritten bytes must
// (a) decode back to the new fields and (b) preserve every other
// field byte-for-byte so the upstream sees the agent's exact client
// metadata.
func TestChHelloPlaceholderInjection(t *testing.T) {
	original := ChHello{
		ClientName:       "agent-cli",
		VersionMajor:     1,
		VersionMinor:     0,
		ProtocolRevision: 54448,
		Database:         "default",
		Username:         "CLAWPATROL_PH_user",
		Password:         "CLAWPATROL_PH_pass",
	}
	wire := chBuildHelloWire(t, original)

	parsed, _, err := chReadHello(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("chReadHello: %v", err)
	}
	parsed.Username = "real-user"
	parsed.Password = "real-pass"
	rewrittenWire := chBuildHelloWire(t, parsed)

	final, _, err := chReadHello(bytes.NewReader(rewrittenWire))
	if err != nil {
		t.Fatalf("chReadHello rewritten: %v", err)
	}
	if final.Username != "real-user" || final.Password != "real-pass" {
		t.Errorf("injection failed: got user=%q pass=%q", final.Username, final.Password)
	}
	if final.ClientName != original.ClientName ||
		final.Database != original.Database ||
		final.VersionMajor != original.VersionMajor ||
		final.ProtocolRevision != original.ProtocolRevision {
		t.Errorf("non-credential fields drifted: %+v vs %+v", final, original)
	}
}

// TestChHelloRejectsNonHello asserts chReadHello refuses packets whose
// leading code isn't ClientCodeHello (0). Important because the
// runtime branches off the result and we don't want a Query packet to
// be silently treated as a Hello.
func TestChHelloRejectsNonHello(t *testing.T) {
	bad := []byte{byte(chgoproto.ClientCodeQuery)}
	if _, _, err := chReadHello(bytes.NewReader(bad)); err == nil {
		t.Errorf("chReadHello accepted non-Hello packet")
	}
}

// TestChEncodeException pins the Exception-packet wire format the
// runtime emits on policy deny: ServerCodeException byte, error code
// 497 (ACCESS_DENIED), exception name "DB::Exception", caller-
// supplied message, empty stack, and has_nested = 0. ClickHouse
// clients render the message as
// "DB::Exception: ACCESS_DENIED: <reason>" on the user-facing side.
func TestChEncodeException(t *testing.T) {
	const reason = "denied by policy"
	out := chEncodeException(reason)

	r := chgoproto.NewReader(bytes.NewReader(out))
	code, err := r.UInt8()
	if err != nil {
		t.Fatalf("read packet code: %v", err)
	}
	if chgoproto.ServerCode(code) != chgoproto.ServerCodeException {
		t.Errorf("packet code = %d, want %d", code, chgoproto.ServerCodeException)
	}
	var exc chgoproto.Exception
	if err := exc.DecodeAware(r, 0); err != nil {
		t.Fatalf("decode exception: %v", err)
	}
	if exc.Code != chgoproto.ErrAccessDenied {
		t.Errorf("Code = %d, want %d", exc.Code, chgoproto.ErrAccessDenied)
	}
	if exc.Name != "DB::Exception" {
		t.Errorf("Name = %q, want DB::Exception", exc.Name)
	}
	if exc.Message != reason {
		t.Errorf("Message = %q, want %q", exc.Message, reason)
	}
	if exc.Stack != "" {
		t.Errorf("Stack = %q, want empty", exc.Stack)
	}
	if exc.Nested {
		t.Errorf("Nested = true, want false")
	}
}

// TestParseChSQL covers the matcher-input extractor across the rule
// shapes the v14 SQL family supports: verb derivation from the
// statement type, table refs walked out of FROM/JOIN/INTO/DROP TABLE,
// trailing FORMAT/SETTINGS chopped before the AST parser sees them
// (the parser doesn't accept those in every position the server
// does), and the parser-failure fallback.
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
				Statement: "SELECT id FROM users FORMAT JSON",
			},
		},
		{
			"insert with settings trailer",
			"INSERT INTO events (ts, body) VALUES (now(), 'x') SETTINGS max_insert_threads = 4",
			chSQLInfo{
				Verb:      "insert",
				Tables:    []string{"events"},
				Statement: "INSERT INTO events (ts, body) VALUES (now(), 'x') SETTINGS max_insert_threads = 4",
			},
		},
		{
			"select aggregate function",
			"SELECT count() FROM events",
			chSQLInfo{
				Verb:      "select",
				Tables:    []string{"events"},
				Functions: []string{"count"},
				Statement: "SELECT count() FROM events",
			},
		},
		{
			"join extracts both tables",
			"SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			chSQLInfo{
				Verb:      "select",
				Tables:    []string{"tokens", "users"},
				Statement: "SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			},
		},
		{
			"drop table",
			"DROP TABLE events",
			chSQLInfo{
				Verb:      "drop",
				Tables:    []string{"events"},
				Statement: "DROP TABLE events",
			},
		},
		{
			"qualified table preserves db",
			"SELECT * FROM analytics.events",
			chSQLInfo{
				Verb:      "select",
				Tables:    []string{"analytics.events"},
				Statement: "SELECT * FROM analytics.events",
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

// TestParseChSQLVerbFallback covers the parser-failure path: when
// AfterShip's parser rejects the syntax (some ALTER permutations,
// non-standard system commands, …) we still surface a verb sniffed
// from the first keyword so verb-based rules keep firing.
func TestParseChSQLVerbFallback(t *testing.T) {
	// Construct an input the AST parser will refuse but the sniffer
	// can still produce "system" out of.
	sql := "SYSTEM ${{not_a_real_thing}}"
	got := parseChSQL(sql)
	if got.Verb != "system" {
		t.Errorf("fallback verb = %q, want system", got.Verb)
	}
	if got.Statement != sql {
		t.Errorf("fallback dropped Statement: %q", got.Statement)
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

// TestChAgentToServerForwardsQuery exercises the agent → server pump
// end-to-end: build a Query packet on the "agent" side of an
// in-memory pipe, run chAgentToServer with an upstream io.Writer
// capturing the forwarded bytes, then assert that the upstream
// packet decodes back to a Query with the same SQL body and the
// agent's Compression choice is preserved verbatim — the gateway
// must not silently flip the flag, since that desyncs subsequent
// Data block framing on the inner hop.
func TestChAgentToServerForwardsQuery(t *testing.T) {
	const sql = "SELECT 1"
	const revision = 54448

	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	defer mock.Conn.Close()

	q := chgoproto.Query{
		ID:          "qid-1",
		Body:        sql,
		Stage:       chgoproto.StageComplete,
		Compression: chgoproto.CompressionEnabled,
		Info: chgoproto.ClientInfo{
			ProtocolVersion: revision,
			Major:           24,
			Minor:           8,
			Interface:       chgoproto.InterfaceTCP,
			Query:           chgoproto.ClientQueryInitial,
			InitialUser:     "alice",
		},
	}
	// Query.EncodeAware emits the ClientCodeQuery byte itself.
	var agentBuf chgoproto.Buffer
	q.EncodeAware(&agentBuf, revision)

	// chAgentToServer reads from a chgoproto.Reader; close the input
	// after the packet so the loop hits EOF and returns.
	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer

	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred")

	if upstream.Len() == 0 {
		t.Fatal("upstream got no bytes")
	}
	out := upstream.Bytes()
	if chgoproto.ClientCode(out[0]) != chgoproto.ClientCodeQuery {
		t.Fatalf("upstream packet code = %d, want ClientCodeQuery", out[0])
	}
	r := chgoproto.NewReader(bytes.NewReader(out[1:]))
	var got chgoproto.Query
	if err := got.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode upstream Query: %v", err)
	}
	if got.Body != sql {
		t.Errorf("Body = %q, want %q", got.Body, sql)
	}
	if got.Compression != chgoproto.CompressionEnabled {
		t.Errorf("Compression = %d, want Enabled (must preserve agent's choice)", got.Compression)
	}
}

// chBuildSampleBlock returns a small Block populated with a single
// UInt32 column so the codec paths have a non-trivial wire payload
// to round-trip in the Data tests.
func chBuildSampleBlock(t *testing.T) *chproto.Block {
	t.Helper()
	block := chproto.NewBlock()
	if err := block.AddColumn("n", column.Type("UInt32")); err != nil {
		t.Fatalf("AddColumn: %v", err)
	}
	if err := block.Append(uint32(1)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := block.Append(uint32(2)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	return block
}

// TestChHandleDataUncompressed pins the uncompressed Data block path:
// the gateway round-trips the block through Block.Decode → Block.Encode
// and forwards a wire-equivalent packet. We compare upstream bytes by
// re-decoding rather than byte-by-byte because Block.Encode emits a
// canonical custom-serialization byte and the original encoder did the
// same — but some helpers are sensitive to capacity/order, so the
// shape-equivalence check is the contract worth pinning.
func TestChHandleDataUncompressed(t *testing.T) {
	const revision = 54448
	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	defer mock.Conn.Close()

	block := chBuildSampleBlock(t)
	var agentBuf chgoproto.Buffer
	agentBuf.PutByte(byte(chgoproto.ClientCodeData))
	chgoproto.ClientData{TableName: "t1"}.EncodeAware(&agentBuf, revision)
	if err := block.Encode(&agentBuf, uint64(revision)); err != nil {
		t.Fatalf("encode block: %v", err)
	}

	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred")

	out := upstream.Bytes()
	if len(out) == 0 || chgoproto.ClientCode(out[0]) != chgoproto.ClientCodeData {
		t.Fatalf("first byte = %d, want ClientCodeData", out[0])
	}
	r := chgoproto.NewReader(bytes.NewReader(out[1:]))
	var hdr chgoproto.ClientData
	if err := hdr.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if hdr.TableName != "t1" {
		t.Errorf("TableName = %q, want t1", hdr.TableName)
	}
	got := chproto.NewBlock()
	if err := got.Decode(r, uint64(revision)); err != nil {
		t.Fatalf("decode upstream block: %v", err)
	}
	if got.Rows() != 2 || len(got.Columns) != 1 {
		t.Errorf("upstream block rows=%d cols=%d, want rows=2 cols=1", got.Rows(), len(got.Columns))
	}

	if !chHasEvent(mock.events, "data") {
		t.Errorf("expected a data event, got %+v", mock.events)
	}
}

// TestChHandleDataCompressedForwardsOpaquely covers the compressed
// path: a Query with Compression=Enabled followed by a Data packet
// whose block payload is wrapped in one ch-go/compress chunk. The
// gateway must (a) forward the Query verbatim (compression flag
// preserved), (b) forward the [code+name] header, and (c) forward
// the compressed chunk bytes byte-for-byte without re-encoding —
// because the agent's compression context is what the upstream
// expects to decode.
func TestChHandleDataCompressedForwardsOpaquely(t *testing.T) {
	const revision = 54448
	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	defer mock.Conn.Close()

	// Build the Query packet (Compression=Enabled).
	q := chgoproto.Query{
		ID: "qid-1", Body: "SELECT 1",
		Stage:       chgoproto.StageComplete,
		Compression: chgoproto.CompressionEnabled,
		Info: chgoproto.ClientInfo{
			ProtocolVersion: revision, Major: 24, Minor: 8,
			Interface:   chgoproto.InterfaceTCP,
			Query:       chgoproto.ClientQueryInitial,
			InitialUser: "alice",
		},
	}
	var agentBuf chgoproto.Buffer
	q.EncodeAware(&agentBuf, revision)
	agentBuf.PutByte(byte(chgoproto.ClientCodeData))
	chgoproto.ClientData{TableName: "t1"}.EncodeAware(&agentBuf, revision)

	// Encode the block uncompressed into a scratch buffer, then run
	// it through compress.Writer to produce a single chunk on the
	// wire. ClickHouse's writer can split blocks across chunks past
	// MaxCompressionBuffer, but the small block here fits in one.
	block := chBuildSampleBlock(t)
	var raw chgoproto.Buffer
	if err := block.Encode(&raw, uint64(revision)); err != nil {
		t.Fatalf("encode raw block: %v", err)
	}
	w := chcompress.NewWriter(chcompress.LevelZero, chcompress.LZ4)
	if err := w.Compress(raw.Buf); err != nil {
		t.Fatalf("compress: %v", err)
	}
	chunkBytes := append([]byte(nil), w.Data...)
	agentBuf.Buf = append(agentBuf.Buf, chunkBytes...)

	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred")

	out := upstream.Bytes()

	// Strip the Query frame off the upstream output by re-decoding it.
	r := chgoproto.NewReader(bytes.NewReader(out))
	if code, err := r.UInt8(); err != nil || chgoproto.ClientCode(code) != chgoproto.ClientCodeQuery {
		t.Fatalf("first packet code = %d (err=%v), want ClientCodeQuery", code, err)
	}
	var fwdQ chgoproto.Query
	if err := fwdQ.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode forwarded Query: %v", err)
	}
	if fwdQ.Compression != chgoproto.CompressionEnabled {
		t.Errorf("forwarded Compression = %d, want Enabled", fwdQ.Compression)
	}

	// Next: the Data header.
	if code, err := r.UInt8(); err != nil || chgoproto.ClientCode(code) != chgoproto.ClientCodeData {
		t.Fatalf("second packet code = %d (err=%v), want ClientCodeData", code, err)
	}
	var fwdHdr chgoproto.ClientData
	if err := fwdHdr.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode forwarded ClientData: %v", err)
	}
	if fwdHdr.TableName != "t1" {
		t.Errorf("forwarded TableName = %q, want t1", fwdHdr.TableName)
	}

	// Bytes after the Data header on the upstream must equal the
	// compressed chunk byte-for-byte — the gateway must not have
	// re-encoded the column payload.
	tail, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if diff := cmp.Diff(chunkBytes, tail); diff != "" {
		t.Errorf("compressed chunk bytes diverged from agent's wire (-agent +upstream):\n%s", diff)
	}

	if !chHasEvent(mock.events, "data") {
		t.Errorf("expected a data event, got %+v", mock.events)
	}
}

func chHasEvent(events []runtime.ConnEvent, verb string) bool {
	for _, e := range events {
		if e.Verb == verb {
			return true
		}
	}
	return false
}

// TestChAgentToServerDeniesQuery confirms the deny path: a Query
// matched by a deny rule must (a) write a server Exception packet to
// the agent's Conn and (b) NOT forward anything to upstream.
func TestChAgentToServerDeniesQuery(t *testing.T) {
	const sql = "INSERT INTO events VALUES (1)"
	const revision = 54448

	rule := chRuleSQL(t, "deny-insert",
		map[string]any{"verb": []any{"insert"}}, "deny", "writes blocked", 100)
	ep := chBuildEndpoint(t, rule)
	mock, agentSide := chNewMockHandle(t, ep)
	defer agentSide.Close()
	defer mock.Conn.Close()

	q := chgoproto.Query{
		ID: "qid-1", Body: sql,
		Stage: chgoproto.StageComplete,
		Info: chgoproto.ClientInfo{
			ProtocolVersion: revision, Major: 24, Minor: 8,
			Interface:   chgoproto.InterfaceTCP,
			Query:       chgoproto.ClientQueryInitial,
			InitialUser: "alice",
		},
	}
	// Query.EncodeAware emits the ClientCodeQuery byte itself.
	var agentBuf chgoproto.Buffer
	q.EncodeAware(&agentBuf, revision)
	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer

	read := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := agentSide.Read(buf)
		read <- append([]byte(nil), buf[:n]...)
	}()

	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred")

	if upstream.Len() != 0 {
		t.Errorf("denied query forwarded %d bytes upstream", upstream.Len())
	}
	got := <-read
	if len(got) == 0 || chgoproto.ServerCode(got[0]) != chgoproto.ServerCodeException {
		t.Errorf("agent did not receive Exception packet; first byte = %d", got[0])
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
