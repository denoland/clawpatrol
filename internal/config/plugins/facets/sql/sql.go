// Package sql is the SQL protocol-family facet. It owns the SQL CEL
// environment (verb / tables / functions / statement, exposed as
// fields on the `sql` variable), the matcher that walks a parsed SQL
// statement, the Meta type wire-frame frontends (postgres,
// clickhouse) populate on match.Request.Meta, and the per-family
// report fields the dashboard shows for a SQL query.
//
// SQL endpoints derive Meta themselves from the wire frame (the
// postgres / clickhouse runtimes parse the Query message and stash
// a *Meta on the request before dispatch), so PrepareRequest is a
// no-op. The matcher type-asserts req.Meta to *Meta and fails the
// match cleanly when the assertion fails — e.g. when an https-
// family request accidentally reaches a sql rule.
package sql

import (
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
)

// Fields is the CEL-facing view of a SQL statement. Exposed as
// the `sql` variable in rule conditions (`sql.verb`, `sql.tables`,
// `sql.functions`, `sql.statement`, `sql.database`). The plural
// `functions` matches the multi-valued shape (a statement can
// reference multiple functions) and parallels `tables`.
type Fields struct {
	Verb      string   `cel:"verb"`
	Tables    []string `cel:"tables"`
	Functions []string `cel:"functions"`
	Statement string   `cel:"statement"`
	Database  string   `cel:"database"`
}

// Meta carries the per-request SQL fields the matcher reads. The
// postgres and clickhouse endpoint runtimes build one of these from
// the parsed wire frame and assign it to match.Request.Meta.
type Meta struct {
	Verb      string   // select | insert | update | delete | merge | ...
	Tables    []string // unqualified table names referenced
	Functions []string // unqualified function names called
	Statement string   // the raw text — exposed for `statement` /
	// `statement_regex` matchers
	Database string // session-scoped database name; postgres
	// StartupMessage `database`, clickhouse_native Hello
	// `default_database`, clickhouse_https `?database` query param
	// or `X-ClickHouse-Database` header. Case-sensitive — postgres
	// treats database names as identifiers. Mid-session changes
	// (postgres `\connect`, `USE` in dialects that support it) are
	// not tracked in v1; the session-start value is canonical.
	// The activation builder also pulls it from req.Database (req
	// wins when both set), letting the protocol runtime wire either
	// source.
}

// Facet is the SQL facet Runtime. Singleton.
type Facet struct{}

// Name reports the family identifier this facet handles.
func (Facet) Name() string { return "sql" }

// EndpointFamilies enumerates endpoint families a sql rule may
// attach to.
func (Facet) EndpointFamilies() []string { return []string{"sql"} }

// Transport returns "" because the SQL family doesn't share the
// HTTPS-MITM dispatch path. Each SQL endpoint plugin (postgres,
// clickhouse_native, ...) owns its own wire-protocol handler and
// gets dispatched on the protocol's well-known port instead of
// through SNI peek on 443.
func (Facet) Transport() string { return "" }

// HITLQueryLabel is the dashboard / Slack label for a SQL query.
func (Facet) HITLQueryLabel() string { return "Query" }

// HostIsResource reports that a SQL request's Host is typically a
// virtual IP, not a label the operator would recognise.
func (Facet) HostIsResource() bool { return false }

// ReportFields declares the per-family columns the SQL facet emits.
func (Facet) ReportFields() []facet.ReportFieldSpec {
	return []facet.ReportFieldSpec{
		{Name: "verb", Kind: facet.ReportString, Label: "Verb"},
		{Name: "tables", Kind: facet.ReportStringList, Label: "Tables"},
		{Name: "functions", Kind: facet.ReportStringList, Label: "Functions"},
		{Name: "statement", Kind: facet.ReportString, Label: "Statement"},
		{Name: "database", Kind: facet.ReportString, Label: "Database"},
	}
}

// PrepareRequest is a no-op: SQL endpoint runtimes set req.Meta
// directly from the wire frame.
func (Facet) PrepareRequest(*match.Request) {}

// Report extracts the SQL report fields from a request. When Meta
// isn't a *Meta (e.g. a request that never ran through a SQL
// frontend) the result is empty rather than panicking.
func (Facet) Report(req *match.Request) map[string]any {
	m, _ := req.Meta.(*Meta)
	if m == nil {
		return nil
	}
	return map[string]any{
		"verb":      m.Verb,
		"tables":    m.Tables,
		"functions": m.Functions,
		"statement": m.Statement,
		"database":  databaseOf(req, m),
	}
}

// databaseOf returns the request's database, preferring the
// req-level field (set by the protocol runtime alongside Meta) and
// falling back to meta.Database when req-level isn't set. Two-source
// shape lets the protocol runtimes wire only one of them and still
// have the dashboard / matcher see the value.
func databaseOf(req *match.Request, m *Meta) string {
	if req != nil && req.Database != "" {
		return req.Database
	}
	if m != nil {
		return m.Database
	}
	return ""
}

func init() {
	facet.Register(Facet{})
}

// CELContrib declares the SQL facet's CEL contribution: the `sql`
// variable backed by Fields and the path lists CompileCondition needs.
//
// lowercasedPaths: sql.verb's activation value is lowercased so
// rules written as `sql.verb == "SELECT"` match a select statement.
//
// truncatablePaths: every SQL field, because the wire frontends
// (postgres pgClientToServer, clickhouse_native chHandleQuery) feed
// the matcher one piece of text — the raw statement — and every
// CEL field (verb, tables, functions, statement) is derived from
// the same parsed bytes. When the frontend caps the frame, all four
// are simultaneously untrustworthy — they become CEL unknowns, so
// any condition whose outcome depends on one fails closed on a
// truncated request.
//
// Note credential and database are intentionally absent: they
// resolve off-wire (StartupMessage user / database, Hello username
// / database, HTTPS query+header), never from frame bytes, so
// predicates on either still evaluate correctly on a truncated
// request. The dispatcher applies r.Credential before the matcher
// runs (config/runtime/dispatch.go), and the database value flows
// through req.Database / meta.Database which the wire frontend
// populates before any SQL bytes are read.
// unparseablePaths declares the SQL fields a wire frontend's parser
// derives from the Query bytes — verb, tables, functions. When the
// parser refuses the input, the frontend leaves these zero and sets
// req.Unparseable=true; the matcher then marks these paths as CEL
// unknowns and any rule whose outcome depends on one is denied.
//
// sql.statement is intentionally absent: the frontend populates it
// with the raw bytes regardless of parse success, so a rule keyed on
// `sql.statement` / `sql.statement.matches(...)` can still evaluate
// honestly on an unparseable request.
func (Facet) CELContrib() facet.CELContrib {
	return facet.CELContrib{
		EnvOptions: []cel.EnvOption{
			ext.NativeTypes(
				reflect.TypeFor[Fields](),
				ext.ParseStructTags(true),
			),
			cel.Variable("sql", cel.ObjectType("sql.Fields")),
		},
		AddActivation:    addActivation,
		LowercasedPaths:  []string{"sql.verb"},
		TruncatablePaths: []string{"sql.verb", "sql.tables", "sql.functions", "sql.statement"},
		UnparseablePaths: []string{"sql.verb", "sql.tables", "sql.functions"},
	}
}

// NewMatcher compiles a CEL condition into a Matcher. Delegates to
// the package-level composer (the sql family composes only its own
// sql facet today — postgres / clickhouse_native wire protocols are
// binary, not HTTPS, so there is no http facet to add).
func (f Facet) NewMatcher(condition string) (match.Matcher, error) {
	m, _, err := facet.Compose(f.Name(), condition)
	return m, err
}

func addActivation(req *match.Request, act map[string]any) bool {
	if req == nil {
		return false
	}
	meta, _ := req.Meta.(*Meta)
	if meta == nil {
		return false
	}
	act["sql"] = &Fields{
		Verb:      strings.ToLower(meta.Verb),
		Tables:    coalesceList(meta.Tables),
		Functions: coalesceList(meta.Functions),
		Statement: meta.Statement,
		Database:  databaseOf(req, meta),
	}
	return true
}

func coalesceList(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
