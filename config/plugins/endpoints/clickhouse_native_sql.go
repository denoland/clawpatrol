package endpoints

// SQL extractor for the clickhouse_native runtime's matcher input.
// Parses ClickHouse SQL via AfterShip/clickhouse-sql-parser, walks
// the AST to harvest tables / functions, and derives the verb from
// the top-level statement type. The shape (chSQLInfo) mirrors
// postgres's pgInfo so the SQL family matcher consumes both
// endpoints' output without per-plugin special cases.

import (
	"fmt"
	"regexp"
	"strings"

	chparser "github.com/AfterShip/clickhouse-sql-parser/parser"
)

// chSQLTrailerRE strips ClickHouse-specific trailers a query may carry
// after the body proper. AfterShip's parser doesn't accept these in
// every position the server does (e.g. `INSERT … VALUES … SETTINGS …`
// fails), so we chop them off the input before parsing. The Statement
// field on chSQLInfo still carries the original SQL.
var chSQLTrailerRE = regexp.MustCompile(`(?is)\s+(?:SETTINGS\s+.*|FORMAT\s+\S+\s*)$`)

type chSQLInfo struct {
	Verb      string
	Tables    []string
	Functions []string
	Statement string // raw, untrimmed — fed to statement / statement_regex matchers
	// UseDatabase carries the target of a top-level `USE db` statement.
	// The wire pump consults this after a matched-and-allowed Query so a
	// session-scoped database tracker can swap to the new value and
	// subsequent statements report the right `sql.database` to the
	// matcher. Empty for non-USE statements.
	UseDatabase string
}

// parseChSQL extracts verb / tables / functions / statement for the
// SQL matcher. The second return is the unparseable flag — true when
// the AST parser refused the input.
//
// Contract (mirrors the Truncated shape — see match.Request.Unparseable):
//
//   - Parse succeeds → unparseable=false, every facet populated.
//   - Parse fails    → unparseable=true,  only Statement populated
//     (Verb/Tables/Functions left zero). The runtime stashes the
//     flag on match.Request.Unparseable, and the dispatcher synth-
//     denies any rule whose CEL reads the unset facets.
//
// No verb-sniffing or shape-specific rewrites: any input the parser
// refuses (CTE-prefixed INSERTs, exotic system commands, syntax
// errors) goes down the same fail-closed path. That keeps the
// contract operators reason about consistent across query shapes
// and avoids silently-disabled write gates when the sniff happens
// to extract a less-restrictive verb than the real intent.
func parseChSQL(sql string) (chSQLInfo, bool) {
	info := chSQLInfo{Statement: sql}
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return info, false
	}

	parseInput := chSQLTrailerRE.ReplaceAllString(trimmed, "")
	stmts, err := chparser.NewParser(parseInput).ParseStmts()
	if err != nil || len(stmts) == 0 {
		return info, true
	}

	// Multi-statement queries: the verb tracks the first statement, but
	// tables / functions are unioned across all of them so a rule that
	// denies access to `secrets` still fires when `secrets` is the
	// second statement in a "use db; select * from secrets" pair.
	info.Verb = chVerbFromStmt(stmts[0])
	// `USE db` at the head of the packet is the wire-level signal that
	// the agent wants subsequent statements interpreted against `db`.
	// We surface the target so the wire pump can update session state
	// after the matcher allows it through. Only the head statement
	// counts — `USE` inside a CTE / subquery has no effect on session
	// scope, and a `SELECT … ; USE other; …` chain leaves the session
	// on `other` only because the trailing USE happens last, which the
	// wire pump can't replay statement-by-statement (clickhouse-server
	// either rejects multi-statement queries or runs them atomically).
	if u, ok := stmts[0].(*chparser.UseStmt); ok && u != nil && u.Database != nil {
		info.UseDatabase = u.Database.Name
	}
	tables, funcs := chWalkSQL(stmts)
	info.Tables = chSortedKeys(tables)
	info.Functions = chSortedKeys(funcs)
	return info, false
}

// chWalkSQL walks every AST in stmts and collects the table refs and
// function names the SQL matcher cares about.
func chWalkSQL(stmts []chparser.Expr) (map[string]struct{}, map[string]struct{}) {
	tables := map[string]struct{}{}
	funcs := map[string]struct{}{}
	for _, stmt := range stmts {
		chparser.Walk(stmt, func(node chparser.Expr) bool {
			switch n := node.(type) {
			case *chparser.TableIdentifier:
				tables[chTableName(n)] = struct{}{}
			case *chparser.FunctionExpr:
				if n.Name != nil {
					funcs[strings.ToLower(n.Name.Name)] = struct{}{}
				}
			}
			return true
		})
	}
	return tables, funcs
}

// chTableName renders a TableIdentifier as `db.table` or `table`
// depending on whether the parser captured a database qualifier. Lower
// cased so glob rules don't have to special-case casing.
func chTableName(t *chparser.TableIdentifier) string {
	if t == nil || t.Table == nil {
		return ""
	}
	if t.Database != nil && t.Database.Name != "" {
		return strings.ToLower(t.Database.Name + "." + t.Table.Name)
	}
	return strings.ToLower(t.Table.Name)
}

// chVerbFromStmt maps a parsed statement node to a lowercase verb
// string aligned with the SQL matcher's vocabulary.
func chVerbFromStmt(stmt chparser.Expr) string {
	switch s := stmt.(type) {
	case *chparser.SelectQuery:
		return "select"
	case *chparser.InsertStmt:
		return "insert"
	case *chparser.DropStmt:
		return "drop"
	case *chparser.UseStmt:
		return "use"
	case *chparser.SetStmt:
		return "set"
	case *chparser.OptimizeStmt:
		return "optimize"
	case *chparser.SystemStmt:
		return "system"
	case *chparser.CheckStmt:
		return "check"
	case *chparser.RenameStmt:
		return "rename"
	case *chparser.ExplainStmt:
		return "explain"
	case *chparser.ShowStmt:
		return "show"
	case *chparser.DescribeStmt:
		return "describe"
	case *chparser.GrantPrivilegeStmt:
		return "grant"
	case *chparser.AlterTable:
		return "alter"
	case *chparser.CTEStmt:
		// WITH … followed by a SELECT/INSERT — surface the underlying
		// verb so rules that gate writes don't get fooled by a CTE wrap.
		if s != nil && s.Expr != nil {
			return chVerbFromStmt(s.Expr)
		}
		return "with"
	}
	// Fallback: derive from concrete type name, e.g.
	// `*parser.CreateTable` → "create".
	name := fmt.Sprintf("%T", stmt)
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, "Stmt")
	name = strings.TrimSuffix(name, "Query")
	if idx := chFirstUpperBoundary(name); idx > 0 {
		name = name[:idx]
	}
	return strings.ToLower(name)
}

// chFirstUpperBoundary finds the index of the second uppercase letter
// in s, treating s[:i] as the leading word in a CamelCase identifier
// (e.g. "CreateTable" → 6, returning "Create").
func chFirstUpperBoundary(s string) int {
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return i
		}
	}
	return 0
}

// chSortedKeys returns the keys of m in stable lexical order. Map
// iteration order is randomized in Go, so without sorting the matcher
// would see jittery `tables=[...]` output run-to-run, breaking
// snapshot-style assertions and dashboard event diffing.
func chSortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// chSummary renders a one-line description of a SQL meta for the
// dashboard event card / HITL prompt. Mirrors pgSummary — keeping the
// shape consistent across SQL families so the dashboard's filter UI
// doesn't need per-plugin special cases.
func chSummary(info chSQLInfo) string {
	var parts []string
	if info.Verb != "" {
		parts = append(parts, strings.ToUpper(info.Verb))
	} else {
		// Unparseable query — surface the marker so dashboard event
		// cards / HITL prompts read "UNPARSEABLE <stmt>" rather than
		// a leading-blank " <stmt>".
		parts = append(parts, "UNPARSEABLE")
	}
	if len(info.Tables) > 0 {
		parts = append(parts, "tables=["+strings.Join(info.Tables, ",")+"]")
	}
	if info.Statement != "" {
		s := info.Statement
		if len(s) > 80 {
			s = s[:80] + "..."
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}
