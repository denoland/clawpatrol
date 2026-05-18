package endpoints

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	chcompress "github.com/ClickHouse/ch-go/compress"
	chgoproto "github.com/ClickHouse/ch-go/proto"
	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	chproto "github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"github.com/google/go-cmp/cmp"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"

	_ "github.com/denoland/clawpatrol/config/plugins/facets/sql"
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

func TestChHelloRejectsServerExceptionPacket(t *testing.T) {
	// ServerCodeException is what ClickHouse sends on auth failure. It must
	// not be interpreted as a partially valid client Hello.
	bad := []byte{byte(chgoproto.ServerCodeException)}
	if _, _, err := chReadHello(bytes.NewReader(bad)); err == nil {
		t.Fatal("chReadHello accepted server Exception packet")
	}
}

// TestParseChSQL covers the matcher-input extractor across the rule
// shapes the v14 SQL family supports: verb derivation from the
// statement type, table refs walked out of FROM/JOIN/INTO/DROP TABLE,
// trailing FORMAT/SETTINGS chopped before the AST parser sees them
// (the parser doesn't accept those in every position the server
// does).
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
			"use surfaces target database",
			"USE metrics",
			chSQLInfo{
				Verb:        "use",
				Statement:   "USE metrics",
				UseDatabase: "metrics",
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
			got, unparseable := parseChSQL(tc.sql)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseChSQL mismatch (-want +got):\n%s", diff)
			}
			if unparseable {
				t.Errorf("unparseable=true on a query the parser should accept")
			}
		})
	}
}

// TestParseChSQLUnparseable pins the contract change: when AfterShip's
// parser refuses the input, parseChSQL now returns Statement-only +
// unparseable=true. No verb sniff, no shape-specific rewrite — the
// dispatcher's fail-closed-on-unparseable gate (config/runtime/
// dispatch.go) is what surfaces a deny on rules that key on
// parser-derived facets.
//
// Inputs cover the two failure shapes that motivated the change:
//   - CTE-prefixed INSERT (the user-reported analytics workload, which
//     AfterShip's grammar doesn't admit).
//   - Exotic SYSTEM command the AST parser bails on.
//
// Both must produce the same shape — the whole point of the generic
// contract is that "parser failed" is one thing, not a per-shape
// special case.
func TestParseChSQLUnparseable(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{
			name: "cte-prefixed insert",
			sql: "WITH cte AS (SELECT id FROM src) " +
				"INSERT INTO dst SELECT id FROM cte",
		},
		{
			name: "user-reported analytics payload",
			sql: `WITH
    filtered_events AS (
        SELECT toDate(event_time) AS event_date, user_id, event_type,
               revenue, event_time
        FROM raw_events
    )
INSERT INTO daily_user_metrics (event_date, user_id)
SELECT fe.event_date, fe.user_id FROM filtered_events AS fe`,
		},
		{
			name: "exotic system command",
			sql:  "SYSTEM ${{not_a_real_thing}}",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, unparseable := parseChSQL(c.sql)
			if !unparseable {
				t.Fatalf("unparseable=false, want true (parser must refuse the input)")
			}
			if got.Verb != "" {
				t.Errorf("Verb=%q, want \"\" (parser-derived facets must be zero on unparseable)", got.Verb)
			}
			if len(got.Tables) != 0 {
				t.Errorf("Tables=%v, want empty", got.Tables)
			}
			if len(got.Functions) != 0 {
				t.Errorf("Functions=%v, want empty", got.Functions)
			}
			if got.Statement != c.sql {
				t.Errorf("Statement must round-trip verbatim; got %q want %q", got.Statement, c.sql)
			}
		})
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

func chRuleSQL(t *testing.T, name, condition, verdict, reason string, priority int) *config.CompiledRule {
	t.Helper()
	m, err := facet.NewMatcher("sql", condition)
	if err != nil {
		t.Fatalf("compile rule %q: %v", name, err)
	}
	return &config.CompiledRule{
		Name: name, Priority: priority, Condition: condition, Matcher: m,
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

// TestChEvaluateSQLThreadsDatabaseIntoMeta verifies that the
// database argument to chEvaluateSQL — supplied by HandleConn from
// the agent's Hello.Database — lands on the *sqlfacet.Meta the
// matcher reads. Case-sensitive: "metrics" and "Metrics" are
// distinct databases.
func TestChEvaluateSQLThreadsDatabaseIntoMeta(t *testing.T) {
	denyOnDB := chRuleSQL(t, "deny-metrics-drops",
		`sql.database == "metrics" && sql.verb == "drop"`,
		"deny", "metrics is locked", 100)
	ep := chBuildEndpoint(t, denyOnDB)

	t.Run("matches when database equal", func(t *testing.T) {
		mock, _ := chNewMockHandle(t, ep)
		verdict, reason, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred", "metrics", false)
		if verdict != "deny" {
			t.Errorf("DROP on metrics verdict = %q, want deny", verdict)
		}
		if reason != "metrics is locked" {
			t.Errorf("reason = %q, want %q", reason, "metrics is locked")
		}
	})

	t.Run("different case does not match", func(t *testing.T) {
		mock, _ := chNewMockHandle(t, ep)
		verdict, _, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred", "Metrics", false)
		if verdict != "" {
			t.Errorf("DROP on Metrics (mixed case) verdict = %q, want allow", verdict)
		}
	})

	t.Run("empty database does not match", func(t *testing.T) {
		mock, _ := chNewMockHandle(t, ep)
		verdict, _, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred", "", false)
		if verdict != "" {
			t.Errorf("DROP with empty database verdict = %q, want allow", verdict)
		}
	})
}

// TestChEvaluateSQLTruncated pins the per-rule fail-closed dispatch
// for clickhouse: a rule whose CEL reads sql.* synth-denies on a
// truncated request; a credential-only rule still allows. The
// truncation arrives via the new bool flag on chEvaluateSQL — set
// by chHandleQuery when q.Body exceeds chMaxQueryBody.
func TestChEvaluateSQLTruncated(t *testing.T) {
	t.Run("verb rule synth-denies on truncated", func(t *testing.T) {
		denySelect := chRuleSQL(t, "select-allow",
			"sql.verb == 'select'", "allow", "", 100)
		defaultDeny := &config.CompiledRule{
			Name: "default-deny", Priority: -100,
			Outcome: config.Outcome{Verdict: "deny", Reason: "no match"},
		}
		ep := chBuildEndpoint(t, denySelect, defaultDeny)

		mock, _ := chNewMockHandle(t, ep)

		verdict, reason, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "SELECT 1", "ch-cred", "", true)
		if verdict != "deny" {
			t.Errorf("truncated SELECT verdict = %q, want deny (synth)", verdict)
		}
		if reason == "" {
			t.Errorf("synth deny reason must not be empty")
		}
	})

	t.Run("non-truncatable rule still allows on truncated", func(t *testing.T) {
		passThrough := &config.CompiledRule{
			Name:    "allow-all",
			Matcher: match.PassThrough{},
			Outcome: config.Outcome{Verdict: "allow"},
		}
		ep := chBuildEndpoint(t, passThrough)

		mock, _ := chNewMockHandle(t, ep)

		verdict, _, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "anything", "ch-cred", "", true)
		if verdict != "" {
			t.Errorf("truncated passthrough verdict = %q, want allow (empty)", verdict)
		}
	})
}

// TestChEvaluateSQLCTEInsertSynthDenies is the regression for the
// user-reported issue (PR #407 thread): a `WITH … INSERT INTO X
// SELECT …` query that AfterShip's parser refuses must still be
// denied when an `sql.verb == 'insert'` rule is on the endpoint. The
// path is now generic — parser fails → req.Unparseable=true → the
// verb rule synth-denies via the dispatcher's fail-closed gate. No
// CTE-specific rewrite, no verb-sniffing.
func TestChEvaluateSQLCTEInsertSynthDenies(t *testing.T) {
	denyInsert := chRuleSQL(t, "deny-insert",
		"sql.verb == 'insert'", "deny", "writes blocked", 100)
	ep := chBuildEndpoint(t, denyInsert)
	mock, _ := chNewMockHandle(t, ep)

	sql := "WITH cte AS (SELECT id FROM src) INSERT INTO dst SELECT id FROM cte"
	verdict, reason, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, sql, "ch-cred", "", false)
	if verdict != "deny" {
		t.Errorf("CTE+INSERT verdict = %q, want deny (via synth on Unparseable)", verdict)
	}
	if reason == "" {
		t.Errorf("synth deny reason must be non-empty")
	}
	if len(mock.events) != 1 {
		t.Fatalf("expected 1 conn event, got %d", len(mock.events))
	}
	if mock.events[0].Action != "deny" {
		t.Errorf("event action = %q, want deny", mock.events[0].Action)
	}
	// The event's verb is empty because the parser couldn't derive
	// one — surfaces honestly rather than the misleading "with" that
	// the old verb-sniff fallback produced.
	if mock.events[0].Verb != "" {
		t.Errorf("event verb = %q, want \"\" (parser-derived facets are zero on unparseable)", mock.events[0].Verb)
	}
}

// TestChEvaluateSQLAllowsSelectDeniesInsert is the iter 2 acceptance
// criterion in test form: a sql_rule with `verb = ["insert"]` /
// `verdict = "deny"` denies an INSERT and lets a SELECT through. The
// matcher input is the same shape the runtime constructs (Verb /
// Tables / Functions / Statement).
func TestChEvaluateSQLAllowsSelectDeniesInsert(t *testing.T) {
	denyInsert := chRuleSQL(t, "deny-insert",
		"sql.verb == 'insert'", "deny", "writes blocked", 100)
	ep := chBuildEndpoint(t, denyInsert)

	mock, _ := chNewMockHandle(t, ep)

	verdict, reason, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "INSERT INTO events VALUES (1)", "ch-cred", "", false)
	if verdict != "deny" {
		t.Errorf("INSERT verdict = %q, want deny", verdict)
	}
	if reason != "writes blocked" {
		t.Errorf("INSERT reason = %q, want %q", reason, "writes blocked")
	}

	verdict, _, _ = chEvaluateSQL(context.Background(), mock.ConnHandle, "SELECT 1", "ch-cred", "", false)
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
	return func(_ runtime.ApproveCallRequest) runtime.ApproveVerdict {
		return runtime.ApproveVerdict{Decision: decision, Reason: reason, By: "test"}
	}
}

// TestChEvaluateSQLApproveChain covers the third verdict path: rule
// has `approve = [...]`. ConnHandle.Approve runs synchronously; an
// allow lets the query forward, a deny rejects with the approver's
// reason.
func TestChEvaluateSQLApproveChain(t *testing.T) {
	approveCondition := "sql.verb == 'drop'"
	approveRule := &config.CompiledRule{
		Name:      "approve-drops",
		Condition: approveCondition,
		Outcome: config.Outcome{
			Approve: []config.ApproveStage{{Name: "human"}},
		},
	}
	m, err := facet.NewMatcher("sql", approveCondition)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	approveRule.Matcher = m
	ep := chBuildEndpoint(t, approveRule)

	t.Run("approver allows", func(t *testing.T) {
		mock, _ := chNewMockHandle(t, ep)
		mock.Approve = chMockApprove("allow", "ok")
		verdict, _, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred", "", false)
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
		verdict, reason, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred", "", false)
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
		verdict, _, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred", "", false)
		if verdict != "deny" {
			t.Errorf("no Approve → verdict %q, want deny", verdict)
		}
	})
}

// TestChAgentToServerStreamsOversizedQueryBody is the regression for
// the matcher-buffer memory cap. The previous implementation called
// q.DecodeAware up front, which materialised the entire SQL body into
// q.Body before chMaxQueryBody could gate anything — a multi-GiB
// statement would balloon the gateway's heap by a multi-GiB allocation
// just to feed the matcher a 1 MiB prefix. The reworked path reads
// at most chMaxQueryBody bytes into memory and splices the tail
// straight through to upstream; this test pins both halves of that
// contract: the matcher sees a `chMaxQueryBody`-byte head with
// Truncated=true, and the forwarded packet still contains the full
// body verbatim so upstream's compression context stays correct.
func TestChAgentToServerStreamsOversizedQueryBody(t *testing.T) {
	const revision = 54448
	// chMaxQueryBody is 1 MiB; build a body that overshoots by a
	// few bytes so the test is sensitive to off-by-one in the
	// length-prefix / streaming-tail split. The leading bytes spell
	// a recognisable head; the trailing bytes include a sentinel
	// the matcher must NOT see (otherwise the cap is silently bypassed).
	head := []byte("SELECT * FROM t WHERE x = '")
	headPad := bytes.Repeat([]byte{'a'}, chMaxQueryBody-len(head))
	tailSentinel := []byte("__TAIL_SENTINEL__")
	body := append(append(append([]byte{}, head...), headPad...), tailSentinel...)
	if len(body) <= chMaxQueryBody {
		t.Fatalf("test body must exceed chMaxQueryBody (%d) to exercise streaming; got %d", chMaxQueryBody, len(body))
	}

	passThrough := &config.CompiledRule{
		Name: "allow-all", Matcher: match.PassThrough{},
		Outcome: config.Outcome{Verdict: "allow"},
	}
	ep := chBuildEndpoint(t, passThrough)
	mock, _ := chNewMockHandle(t, ep)
	defer func() { _ = mock.Conn.Close() }()

	q := chgoproto.Query{
		ID: "qid-big", Body: string(body),
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

	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

	out := upstream.Bytes()
	if len(out) == 0 || chgoproto.ClientCode(out[0]) != chgoproto.ClientCodeQuery {
		t.Fatalf("upstream first byte = %d, want ClientCodeQuery", out[0])
	}
	r := chgoproto.NewReader(bytes.NewReader(out[1:]))
	var got chgoproto.Query
	if err := got.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode upstream Query: %v", err)
	}
	if got.Body != string(body) {
		t.Errorf("forwarded Body len = %d, want %d (full body must round-trip even though only the head is buffered)", len(got.Body), len(body))
	}
	if got.Compression != chgoproto.CompressionEnabled {
		t.Errorf("forwarded Compression = %d, want Enabled", got.Compression)
	}

	if len(mock.events) != 1 {
		t.Fatalf("expected 1 conn event, got %d: %+v", len(mock.events), mock.events)
	}
	stmt, _ := mock.events[0].Facets["statement"].(string)
	if len(stmt) > chMaxQueryBody {
		t.Errorf("matcher statement len = %d, want <= %d (oversized body must not reach the matcher)", len(stmt), chMaxQueryBody)
	}
	if strings.Contains(stmt, string(tailSentinel)) {
		t.Errorf("matcher statement leaked the tail-sentinel — chMaxQueryBody cap bypassed")
	}
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
	defer func() { _ = mock.Conn.Close() }()

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

	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

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
	defer func() { _ = mock.Conn.Close() }()

	block := chBuildSampleBlock(t)
	var agentBuf chgoproto.Buffer
	agentBuf.PutByte(byte(chgoproto.ClientCodeData))
	chgoproto.ClientData{TableName: "t1"}.EncodeAware(&agentBuf, revision)
	if err := block.Encode(&agentBuf, uint64(revision)); err != nil {
		t.Fatalf("encode block: %v", err)
	}

	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

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
	defer func() { _ = mock.Conn.Close() }()

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
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

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

// chCompressedDataEventSummary returns the Summary of the (single)
// "data" ConnEvent emitted during the test. Used by probe tests that
// pin the new bytes=N (compressed) wording.
func chCompressedDataEventSummary(t *testing.T, events []runtime.ConnEvent) string {
	t.Helper()
	var found *runtime.ConnEvent
	for i := range events {
		if events[i].Verb == "data" {
			if found != nil {
				t.Fatalf("expected exactly one data event, got: %+v", events)
			}
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatalf("no data event in: %+v", events)
	}
	return found.Summary
}

// TestChCompressedDataEventDropsRowsCols pins the option-1a wording
// of the per-Data event on the compressed path: probe-walking forwards
// opaque bytes without materializing the block, so the summary drops
// rows/cols and reports forwarded byte count instead. Regression for
// the old "rows=N cols=M (compressed)" string the Block.Decode-backed
// path emitted.
func TestChCompressedDataEventDropsRowsCols(t *testing.T) {
	const revision = 54448
	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	defer func() { _ = mock.Conn.Close() }()

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
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

	summary := chCompressedDataEventSummary(t, mock.events)
	wantBytes := fmt.Sprintf("bytes=%d", len(chunkBytes))
	if !strings.Contains(summary, wantBytes) {
		t.Errorf("event summary %q missing %q", summary, wantBytes)
	}
	if !strings.Contains(summary, "(compressed)") {
		t.Errorf("event summary %q missing (compressed) marker", summary)
	}
	if strings.Contains(summary, "rows=") || strings.Contains(summary, "cols=") {
		t.Errorf("event summary %q must drop rows/cols on compressed path", summary)
	}
}

// TestChProbeForwardsMultiChunkBlock verifies the probe walks a
// multi-chunk compressed block without re-decoding. Two chunks under
// one ClientData header simulate clickhouse-go's behaviour past
// MaxCompressionBuffer (default 10 MiB): both chunks must reach
// upstream byte-for-byte.
func TestChProbeForwardsMultiChunkBlock(t *testing.T) {
	const revision = 54448
	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	defer func() { _ = mock.Conn.Close() }()

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

	// Two distinct chunks. Real clients flush across chunk boundaries
	// inside one ClientData when a block exceeds MaxCompressionBuffer.
	chunkA := chCompressLZ4Frame(t, []byte("payload-A-aaaaaaaaaaaaaaaaaaaaaaaa"))
	chunkB := chCompressLZ4Frame(t, []byte("payload-B-bbbbbbbb"))
	agentBuf.Buf = append(agentBuf.Buf, chunkA...)
	agentBuf.Buf = append(agentBuf.Buf, chunkB...)

	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

	// Strip the Query frame + Data header; what's left must be both
	// chunks concatenated, byte-for-byte.
	r := chgoproto.NewReader(bytes.NewReader(upstream.Bytes()))
	if code, err := r.UInt8(); err != nil || chgoproto.ClientCode(code) != chgoproto.ClientCodeQuery {
		t.Fatalf("first packet code = %d (err=%v), want ClientCodeQuery", code, err)
	}
	var fwdQ chgoproto.Query
	if err := fwdQ.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode forwarded Query: %v", err)
	}
	if code, err := r.UInt8(); err != nil || chgoproto.ClientCode(code) != chgoproto.ClientCodeData {
		t.Fatalf("second packet code = %d (err=%v), want ClientCodeData", code, err)
	}
	var fwdHdr chgoproto.ClientData
	if err := fwdHdr.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode forwarded ClientData: %v", err)
	}
	tail, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	want := append(append([]byte(nil), chunkA...), chunkB...)
	if diff := cmp.Diff(want, tail); diff != "" {
		t.Errorf("multi-chunk forward (-want +got):\n%s", diff)
	}

	summary := chCompressedDataEventSummary(t, mock.events)
	wantBytes := fmt.Sprintf("bytes=%d", len(chunkA)+len(chunkB))
	if !strings.Contains(summary, wantBytes) {
		t.Errorf("event summary %q missing %q (sum across both chunks)", summary, wantBytes)
	}
}

// TestChProbeRewindsToNextQuery is the regression for option-(3): when
// the probe's lookahead byte turns out to be the next packet's code,
// the rewind path must re-feed it (and any candidate-header bytes the
// probe pulled trying to validate the frame) so the pump dispatches
// the packet correctly. Stream: Query (compressed) → compressed Data
// (one chunk) → Query — upstream must see all three.
func TestChProbeRewindsToNextQuery(t *testing.T) {
	const revision = 54448
	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	defer func() { _ = mock.Conn.Close() }()

	mkQuery := func(id, body string, comp chgoproto.Compression) chgoproto.Query {
		return chgoproto.Query{
			ID: id, Body: body,
			Stage:       chgoproto.StageComplete,
			Compression: comp,
			Info: chgoproto.ClientInfo{
				ProtocolVersion: revision, Major: 24, Minor: 8,
				Interface:   chgoproto.InterfaceTCP,
				Query:       chgoproto.ClientQueryInitial,
				InitialUser: "alice",
			},
		}
	}

	var agentBuf chgoproto.Buffer
	mkQuery("q1", "SELECT 1", chgoproto.CompressionEnabled).EncodeAware(&agentBuf, revision)
	agentBuf.PutByte(byte(chgoproto.ClientCodeData))
	chgoproto.ClientData{TableName: "t1"}.EncodeAware(&agentBuf, revision)
	chunk := chCompressLZ4Frame(t, []byte("payload-some-bytes"))
	agentBuf.Buf = append(agentBuf.Buf, chunk...)
	mkQuery("q2", "SELECT 2", chgoproto.CompressionEnabled).EncodeAware(&agentBuf, revision)

	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

	r := chgoproto.NewReader(bytes.NewReader(upstream.Bytes()))
	// Q1
	if code, err := r.UInt8(); err != nil || chgoproto.ClientCode(code) != chgoproto.ClientCodeQuery {
		t.Fatalf("first packet code = %d (err=%v), want Query", code, err)
	}
	var q1 chgoproto.Query
	if err := q1.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode q1: %v", err)
	}
	if q1.Body != "SELECT 1" {
		t.Errorf("q1.Body = %q, want SELECT 1", q1.Body)
	}
	// Data
	if code, err := r.UInt8(); err != nil || chgoproto.ClientCode(code) != chgoproto.ClientCodeData {
		t.Fatalf("second packet code = %d (err=%v), want Data", code, err)
	}
	var hdr chgoproto.ClientData
	if err := hdr.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode data header: %v", err)
	}
	// Read the chunk worth of bytes (= len(chunk)) — this is the
	// probe's verbatim forward.
	got := make([]byte, len(chunk))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read forwarded chunk: %v", err)
	}
	if diff := cmp.Diff(chunk, got); diff != "" {
		t.Errorf("forwarded chunk diverged (-want +got):\n%s", diff)
	}
	// Q2 — this is the rewind regression. Probe read [0x01, ...24
	// candidate bytes...] and rejected; rewind put them back and
	// the pump dispatched as Query.
	if code, err := r.UInt8(); err != nil || chgoproto.ClientCode(code) != chgoproto.ClientCodeQuery {
		t.Fatalf("third packet code = %d (err=%v), want Query (rewind dispatch)", code, err)
	}
	var q2 chgoproto.Query
	if err := q2.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode q2 after rewind: %v", err)
	}
	if q2.Body != "SELECT 2" {
		t.Errorf("q2.Body after rewind = %q, want SELECT 2", q2.Body)
	}
}

// chCompressLZ4Frame wraps payload in one ch-go/compress LZ4 frame —
// the wire shape every test that exercises the compressed Data path
// (single-chunk, multi-chunk, rewind) needs.
func chCompressLZ4Frame(t *testing.T, payload []byte) []byte {
	t.Helper()
	w := chcompress.NewWriter(chcompress.LevelZero, chcompress.LZ4)
	if err := w.Compress(payload); err != nil {
		t.Fatalf("compress: %v", err)
	}
	return append([]byte(nil), w.Data...)
}

// TestChAgentToServerDeniesQuery confirms the deny path: a Query
// matched by a deny rule must (a) write a server Exception packet to
// the agent's Conn and (b) NOT forward anything to upstream.
func TestChAgentToServerDeniesQuery(t *testing.T) {
	const sql = "INSERT INTO events VALUES (1)"
	const revision = 54448

	rule := chRuleSQL(t, "deny-insert",
		"sql.verb == 'insert'", "deny", "writes blocked", 100)
	ep := chBuildEndpoint(t, rule)
	mock, agentSide := chNewMockHandle(t, ep)
	defer func() { _ = agentSide.Close() }()
	defer func() { _ = mock.Conn.Close() }()

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

	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

	if upstream.Len() != 0 {
		t.Errorf("denied query forwarded %d bytes upstream", upstream.Len())
	}
	got := <-read
	if len(got) == 0 || chgoproto.ServerCode(got[0]) != chgoproto.ServerCodeException {
		t.Errorf("agent did not receive Exception packet; first byte = %d", got[0])
	}
}

// TestChAgentToServerUseDatabaseUpdatesSessionScope is the regression
// for the v1-limitation closure: a `USE metrics` allowed by the
// matcher must roll the session-tracked database forward so the very
// next statement matches against `metrics` instead of the connect-
// time database. The stream is `USE metrics; DROP TABLE events`,
// with a rule that denies `sql.database == "metrics" && sql.verb ==
// "drop"`. The pre-fix code reported the connect-time database for
// every query, so the DROP slipped past the rule and reached
// upstream; with USE-tracking the gateway denies it and the agent
// receives an Exception.
func TestChAgentToServerUseDatabaseUpdatesSessionScope(t *testing.T) {
	const revision = 54448
	rule := chRuleSQL(t, "lock-metrics",
		`sql.database == "metrics" && sql.verb == "drop"`,
		"deny", "metrics is locked", 100)
	ep := chBuildEndpoint(t, rule)
	mock, agentSide := chNewMockHandle(t, ep)
	defer func() { _ = agentSide.Close() }()
	defer func() { _ = mock.Conn.Close() }()

	mkQuery := func(id, body string) []byte {
		q := chgoproto.Query{
			ID: id, Body: body,
			Stage: chgoproto.StageComplete,
			Info: chgoproto.ClientInfo{
				ProtocolVersion: revision, Major: 24, Minor: 8,
				Interface:   chgoproto.InterfaceTCP,
				Query:       chgoproto.ClientQueryInitial,
				InitialUser: "alice",
			},
		}
		var b chgoproto.Buffer
		q.EncodeAware(&b, revision)
		return b.Buf
	}

	var stream bytes.Buffer
	stream.Write(mkQuery("q1", "USE metrics"))
	stream.Write(mkQuery("q2", "DROP TABLE events"))

	agentBytes := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := agentSide.Read(buf)
		agentBytes <- append([]byte(nil), buf[:n]...)
	}()

	reader := chgoproto.NewReader(bytes.NewReader(stream.Bytes()))
	var upstream bytes.Buffer
	// Connect-time database is "default" — the rule must not fire on
	// it; only after USE metrics rolls the tracker forward.
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "default")

	r := chgoproto.NewReader(bytes.NewReader(upstream.Bytes()))
	var bodies []string
	for {
		code, err := r.UInt8()
		if err != nil {
			break
		}
		if chgoproto.ClientCode(code) != chgoproto.ClientCodeQuery {
			t.Fatalf("upstream packet code = %d, want ClientCodeQuery", code)
		}
		var q chgoproto.Query
		if err := q.DecodeAware(r, revision); err != nil {
			t.Fatalf("decode upstream Query: %v", err)
		}
		bodies = append(bodies, q.Body)
	}
	wantBodies := []string{"USE metrics"}
	if diff := cmp.Diff(wantBodies, bodies); diff != "" {
		t.Errorf("upstream Query bodies (-want +got):\n%s", diff)
	}

	exc := <-agentBytes
	if len(exc) == 0 || chgoproto.ServerCode(exc[0]) != chgoproto.ServerCodeException {
		t.Errorf("agent did not receive Exception for the DROP; first byte = %d", exc[0])
	}

	// Pin the per-statement meta: the USE event saw `default` (the
	// pre-swap value), and the DROP event saw `metrics`.
	var useEvent, dropEvent *runtime.ConnEvent
	for i := range mock.events {
		switch mock.events[i].Verb {
		case "use":
			useEvent = &mock.events[i]
		case "drop":
			dropEvent = &mock.events[i]
		}
	}
	if useEvent == nil || dropEvent == nil {
		t.Fatalf("expected use+drop events, got: %+v", mock.events)
	}
	if got, _ := useEvent.Facets["database"].(string); got != "default" {
		t.Errorf("USE event database facet = %q, want %q (pre-swap)", got, "default")
	}
	if got, _ := dropEvent.Facets["database"].(string); got != "metrics" {
		t.Errorf("DROP event database facet = %q, want %q (post-swap)", got, "metrics")
	}
}

// TestChAgentToServerUseDatabaseStickyOnDeny verifies the denied-USE
// path: a `USE metrics` rejected by the matcher must leave the
// session's tracked database untouched, so the next statement still
// reports the pre-USE value to the matcher. Without this, a denied
// USE that the dashboard "knows" failed would still poison every
// downstream `sql.database` predicate for the connection.
func TestChAgentToServerUseDatabaseStickyOnDeny(t *testing.T) {
	const revision = 54448
	rule := chRuleSQL(t, "no-use-metrics",
		`sql.verb == "use" && sql.statement == "USE metrics"`,
		"deny", "use blocked", 100)
	ep := chBuildEndpoint(t, rule)
	mock, agentSide := chNewMockHandle(t, ep)
	defer func() { _ = agentSide.Close() }()
	defer func() { _ = mock.Conn.Close() }()

	mkQuery := func(id, body string) []byte {
		q := chgoproto.Query{
			ID: id, Body: body,
			Stage: chgoproto.StageComplete,
			Info: chgoproto.ClientInfo{
				ProtocolVersion: revision, Major: 24, Minor: 8,
				Interface:   chgoproto.InterfaceTCP,
				Query:       chgoproto.ClientQueryInitial,
				InitialUser: "alice",
			},
		}
		var b chgoproto.Buffer
		q.EncodeAware(&b, revision)
		return b.Buf
	}

	var stream bytes.Buffer
	stream.Write(mkQuery("q1", "USE metrics"))
	stream.Write(mkQuery("q2", "SELECT 1"))

	// Drain the Exception the deny writes to the agent.
	go func() {
		buf := make([]byte, 4096)
		_, _ = agentSide.Read(buf)
	}()

	reader := chgoproto.NewReader(bytes.NewReader(stream.Bytes()))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "default")

	var selectEvent *runtime.ConnEvent
	for i := range mock.events {
		if mock.events[i].Verb == "select" {
			selectEvent = &mock.events[i]
		}
	}
	if selectEvent == nil {
		t.Fatalf("expected select event after denied USE; got: %+v", mock.events)
	}
	if got, _ := selectEvent.Facets["database"].(string); got != "default" {
		t.Errorf("SELECT database after denied USE = %q, want %q (USE must not roll forward on deny)", got, "default")
	}
}

// TestChAgentToServerMultiQueryDenyContinues is the regression for
// the per-Query inspector fix. The earlier shape returned out of the
// pump on deny — that left the gateway "first-Query-only" and let
// an agent smuggle a denied statement after an allowed one (or vice
// versa) by reordering. The pump now mirrors postgres' shape: deny
// writes Exception, the loop keeps reading, and a follow-up Query
// is re-evaluated end-to-end.
//
// Stream: SELECT (allow) → DROP (deny) → SELECT (allow). Upstream
// must see only the two SELECTs; the agent must see one Exception.
func TestChAgentToServerMultiQueryDenyContinues(t *testing.T) {
	const revision = 54448
	rule := chRuleSQL(t, "deny-drop",
		"sql.verb == 'drop'", "deny", "drops blocked", 100)
	ep := chBuildEndpoint(t, rule)
	mock, agentSide := chNewMockHandle(t, ep)
	defer func() { _ = agentSide.Close() }()
	defer func() { _ = mock.Conn.Close() }()

	mkQuery := func(id, body string) []byte {
		q := chgoproto.Query{
			ID:    id,
			Body:  body,
			Stage: chgoproto.StageComplete,
			Info: chgoproto.ClientInfo{
				ProtocolVersion: revision, Major: 24, Minor: 8,
				Interface:   chgoproto.InterfaceTCP,
				Query:       chgoproto.ClientQueryInitial,
				InitialUser: "alice",
			},
		}
		var b chgoproto.Buffer
		q.EncodeAware(&b, revision)
		return b.Buf
	}

	var stream bytes.Buffer
	stream.Write(mkQuery("q1", "SELECT 1"))
	stream.Write(mkQuery("q2", "DROP TABLE events"))
	stream.Write(mkQuery("q3", "SELECT 2"))

	// Drain the agent side asynchronously — net.Pipe is synchronous,
	// so the runtime's Exception write would otherwise block. We
	// loop with a short wait so the goroutine catches the deny even
	// if it's followed quickly by the next Query packet.
	agentBytes := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := agentSide.Read(buf)
		agentBytes <- append([]byte(nil), buf[:n]...)
	}()

	reader := chgoproto.NewReader(bytes.NewReader(stream.Bytes()))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred", "")

	// Upstream must contain q1 and q3 (q2 was denied → not forwarded).
	r := chgoproto.NewReader(bytes.NewReader(upstream.Bytes()))
	var bodies []string
	for {
		code, err := r.UInt8()
		if err != nil {
			break
		}
		if chgoproto.ClientCode(code) != chgoproto.ClientCodeQuery {
			t.Fatalf("upstream packet code = %d, want ClientCodeQuery", code)
		}
		var q chgoproto.Query
		if err := q.DecodeAware(r, revision); err != nil {
			t.Fatalf("decode upstream Query: %v", err)
		}
		bodies = append(bodies, q.Body)
	}
	wantBodies := []string{"SELECT 1", "SELECT 2"}
	if diff := cmp.Diff(wantBodies, bodies); diff != "" {
		t.Errorf("upstream Query bodies (-want +got):\n%s", diff)
	}

	exc := <-agentBytes
	if len(exc) == 0 || chgoproto.ServerCode(exc[0]) != chgoproto.ServerCodeException {
		t.Errorf("agent did not receive Exception; first byte = %d", exc[0])
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
