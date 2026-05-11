// Package sql is the SQL protocol-family facet. It owns the SQL CEL
// environment (verb / tables / functions / statement), the matcher
// that walks a parsed SQL statement, the Meta type wire-frame
// frontends (postgres, clickhouse) populate on match.Request.Meta,
// and the per-family report fields the dashboard shows for a SQL
// query.
//
// SQL endpoints derive Meta themselves from the wire frame (the
// postgres / clickhouse runtimes parse the Query message and stash
// a *Meta on the request before dispatch), so PrepareRequest is a
// no-op. The matcher type-asserts req.Meta to *Meta and fails the
// match cleanly when the assertion fails — e.g. when an https-
// family request accidentally reaches a sql_rule.
package sql

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/plugins/rules"
)

// Meta carries the per-request SQL fields the matcher reads. The
// postgres and clickhouse endpoint runtimes build one of these from
// the parsed wire frame and assign it to match.Request.Meta.
type Meta struct {
	Verb      string   // select | insert | update | delete | merge | ...
	Tables    []string // unqualified table names referenced
	Functions []string // unqualified function names called
	Statement string   // the raw text — exposed for `statement` /
	// `statement_regex` matchers
}

// Facet is the SQL facet Runtime. Singleton.
type Facet struct{}

// Name reports the family identifier this facet handles.
func (Facet) Name() string { return "sql" }

// RuleType reports the HCL rule label that targets this facet.
func (Facet) RuleType() string { return "sql_rule" }

// EndpointFamilies enumerates endpoint families a sql_rule may
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
	}
}

// celEnv is the SQL CEL environment. Built once at init.
var celEnv *cel.Env

func init() {
	env, err := cel.NewEnv(
		ext.Sets(),
		cel.Variable("verb", cel.StringType),
		cel.Variable("tables", cel.ListType(cel.StringType)),
		cel.Variable("functions", cel.ListType(cel.StringType)),
		cel.Variable("statement", cel.StringType),
	)
	if err != nil {
		panic(fmt.Sprintf("sql facet: cel env: %v", err))
	}
	celEnv = env

	f := Facet{}
	facet.Register(f)
	config.Register(rules.PluginFor(f))
}

// NewMatcher compiles a CEL condition into a Matcher. An empty
// condition is the catch-all match-everything case.
func (Facet) NewMatcher(condition string) (match.Matcher, error) {
	if condition == "" {
		return match.PassThrough{}, nil
	}
	return match.CompileCondition(celEnv, condition, buildActivation)
}

func buildActivation(req *match.Request) map[string]any {
	if req == nil {
		return nil
	}
	meta, _ := req.Meta.(*Meta)
	if meta == nil {
		return nil
	}
	return map[string]any{
		"verb":      strings.ToLower(meta.Verb),
		"tables":    coalesceList(meta.Tables),
		"functions": coalesceList(meta.Functions),
		"statement": meta.Statement,
	}
}

func coalesceList(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
