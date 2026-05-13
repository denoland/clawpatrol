package endpoints

// SQL extractor for the postgres endpoint's matcher input. Parses
// SQL via auxten/postgresql-parser (the pure-Go cockroach fork),
// walks the AST to harvest tables / functions, and derives the verb
// from each top-level statement node. Same shape as
// clickhouse_native_sql.go so the SQL family matcher consumes both
// endpoints' output without per-plugin special cases.
//
// Audit reference: denoland/clawpatrol#143 catalogues the regex
// extractor's evasions. The AST path covers most of it for free —
// the parser already knows about comments, string literals, quoted
// identifiers, dollar quotes, and ;-separated batches.
//
// Fallback path: cockroach's grammar isn't postgres — LOCK / VACUUM
// / ANALYZE / REINDEX / REFRESH MATERIALIZED VIEW / CLUSTER /
// SET ROLE / SET SESSION AUTHORIZATION / DO blocks / CALL all
// reject. For each such piece we run a tokenizer-driven sniff: it
// surfaces the verb (including multi-word forms like "set role") and
// re-parses DO block bodies so inner statements still walk the
// matcher (audit §6.5). String / comment / dollar-quote handling in
// the tokenizer keeps the fallback from generating ghost tables.

import (
	"sort"
	"strings"

	pgparser "github.com/auxten/postgresql-parser/pkg/sql/parser"
	"github.com/auxten/postgresql-parser/pkg/sql/sem/tree"
)

// ── Top-level entry points ────────────────────────────────────────────

// parseSQL extracts a single pgInfo for the first top-level
// statement in sql. Used by the ParseStatement plugin contract
// (action fixtures, dashboard previews). For multi-statement
// payloads the wire-protocol gateway calls analyseAll directly so
// each statement walks the matcher.
func parseSQL(sql string) pgInfo {
	a := analyseAll(sql)
	if len(a) == 0 {
		return pgInfo{Statement: strings.TrimSpace(sql)}
	}
	return a[0].Outer
}

// analyseAll tokenises sql into top-level statements and returns one
// analysedStmt per statement. Inner pgInfos surface CTE-hidden DML
// (audit §1.2) and DO block bodies (§6.5) the matcher must see.
func analyseAll(sql string) []analysedStmt {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return []analysedStmt{{Outer: pgInfo{}}}
	}

	// Fast path: whole input parses. The parser handles
	// ;-separated statements natively — multi-statement Q payloads
	// flow through as one Parse call.
	if stmts, err := pgparser.Parse(trimmed); err == nil && len(stmts) > 0 {
		out := make([]analysedStmt, 0, len(stmts))
		for _, s := range stmts {
			out = append(out, analyseAST(s))
		}
		return out
	}

	// Slow path: any single statement that the cockroach grammar
	// rejects (PG-only DDL, DO blocks, CALL, SET ROLE) forces us to
	// split by top-level `;` ourselves and retry parsing each piece.
	// Pieces that still fail use the verb-sniff stub.
	pieces := splitTopLevelStatements(trimmed)
	out := make([]analysedStmt, 0, len(pieces))
	for _, p := range pieces {
		out = append(out, analysePiece(p))
	}
	return out
}

// analysePiece runs one statement piece through the parser, falling
// back to the verb-sniff stub when the cockroach grammar can't
// represent it.
func analysePiece(sql string) analysedStmt {
	if stmts, err := pgparser.Parse(sql); err == nil && len(stmts) > 0 {
		return analyseAST(stmts[0])
	}
	return sniffStmt(sql)
}

// ── AST walk ──────────────────────────────────────────────────────────

// analyseAST builds pgInfo from a parsed statement node. Tables and
// functions are collected via a recursive visit; CTE-hidden DML
// surfaces as a shadow inner pgInfo.
func analyseAST(stmt pgparser.Statement) analysedStmt {
	info := pgInfo{Statement: stmt.SQL}
	info.Verb = verbFromAST(stmt.AST)

	c := &astCollector{tables: map[string]struct{}{}, funcs: map[string]struct{}{}}
	c.visit(stmt.AST)
	info.Tables = sortedKeys(c.tables)
	info.Functions = sortedKeys(c.funcs)

	return analysedStmt{Outer: info, Inner: c.inner}
}

// verbFromAST maps a parsed statement node to the lowercase verb the
// SQL matcher expects. Postgres-specific verbs (and multi-word forms
// like "set role") that the parser doesn't model are surfaced by the
// sniff fallback; this path covers what the parser does model.
//
// `*tree.Select` is preserved as "select" even when it carries a
// `WITH` clause whose CTEs mutate — the inner mutation rides on
// astCollector.inner as a shadow statement, matching the audit
// §1.2 semantics.
func verbFromAST(stmt tree.Statement) string {
	tag := strings.ToLower(stmt.StatementTag())
	// Statement tags are space-separated phrases ("DROP TABLE",
	// "COMMENT ON TABLE", "EXPLAIN ANALYZE (DEBUG)"). For the SQL
	// matcher's `verb` field we surface the first token so existing
	// CEL rules like `sql.verb == "drop"` keep working, while
	// multi-token forms ("comment on table") get the full tag for
	// callers that want to gate the specific shape.
	switch tag {
	case "drop table", "drop view", "drop sequence", "drop index", "drop database", "drop role":
		return strings.Fields(tag)[0]
	case "create table", "create view", "create sequence", "create index", "create database",
		"create role", "create schema", "create statistics", "create changefeed":
		return "create"
	case "alter table", "alter index", "alter sequence", "alter role":
		return "alter"
	case "comment on table", "comment on column", "comment on database", "comment on index":
		return "comment"
	case "rename table", "rename column", "rename database", "rename index":
		return "rename"
	case "commit", "rollback", "begin", "savepoint", "release":
		return tag
	}
	// Default: first token of the tag.
	if i := strings.IndexByte(tag, ' '); i > 0 {
		return tag[:i]
	}
	return tag
}

// astCollector walks an AST and records the tables and functions it
// references. Statement-shaped nodes that the parser exposes
// directly (DropTable.Names, Truncate.Tables, etc.) emit their table
// targets at the case site; expressions recurse so subquery /
// CTE-internal references show up too.
type astCollector struct {
	tables map[string]struct{}
	funcs  map[string]struct{}
	inner  []pgInfo
}

func (c *astCollector) emitTable(name string) {
	if name == "" {
		return
	}
	c.tables[name] = struct{}{}
	// §2.3: schema-qualified names emit the unqualified leaf as a
	// second candidate so rules written either way fire.
	if i := strings.LastIndex(name, "."); i >= 0 && i+1 < len(name) {
		c.tables[name[i+1:]] = struct{}{}
	}
}

// emitTablePattern surfaces a GRANT / REVOKE table target. Cockroach
// models these as TablePatterns — either an UnresolvedName or a
// pattern with a star — so we have to dispatch by concrete type
// rather than going through the generic walker (which would also
// pick up column references inside expressions).
func (c *astCollector) emitTablePattern(p tree.TablePattern) {
	switch t := p.(type) {
	case *tree.UnresolvedName:
		c.emitTable(unresolvedNameToString(t))
	case *tree.TableName:
		c.emitTableName(t)
	}
}

func (c *astCollector) emitTableName(t *tree.TableName) {
	if t == nil {
		return
	}
	unq := string(t.TableName)
	if t.ExplicitSchema && string(t.SchemaName) != "" {
		c.emitTable(string(t.SchemaName) + "." + unq)
	} else {
		c.emitTable(unq)
	}
}

func (c *astCollector) emitFunc(f *tree.FuncExpr) {
	if f == nil || f.Func.FunctionReference == nil {
		return
	}
	name := strings.ToLower(strings.Trim(f.Func.String(), `"`))
	if name == "" {
		return
	}
	c.funcs[name] = struct{}{}
	// Mirror table extraction: schema-qualified function names emit
	// the unqualified leaf too so `function == "dblink"` matches
	// `pg_catalog.dblink(...)`.
	if i := strings.LastIndex(name, "."); i >= 0 && i+1 < len(name) {
		c.funcs[name[i+1:]] = struct{}{}
	}
}

// visit is a hand-rolled walker over the auxten/cockroach AST.
// auxten ships a `walk` helper but its switch is incomplete for
// DDL — DropTable, AlterTable, CreateTable, Truncate, CopyFrom,
// CommentOnTable, Grant, Revoke, Insert, Update, Delete all land in
// UnknownNodes. We hit them explicitly here.
func (c *astCollector) visit(node interface{}) {
	if node == nil {
		return
	}
	switch n := node.(type) {

	// ── Statement-level dispatch ──────────────────────────────────
	case *tree.Select:
		if n.With != nil {
			c.visitCTEs(n.With)
		}
		c.visit(n.Select)
		c.visit(n.OrderBy)
		c.visit(n.Limit)
	case *tree.ParenSelect:
		c.visit(n.Select)
	case *tree.SelectClause:
		for _, e := range n.Exprs {
			c.visit(e)
		}
		c.visit(&n.From)
		if n.Where != nil {
			c.visit(n.Where)
		}
		if n.Having != nil {
			c.visit(n.Having)
		}
		for _, e := range n.GroupBy {
			c.visit(e)
		}
		for _, e := range n.DistinctOn {
			c.visit(e)
		}
	case *tree.UnionClause:
		c.visit(n.Left)
		c.visit(n.Right)
	case *tree.Insert:
		if n.With != nil {
			c.visitCTEs(n.With)
		}
		c.visit(n.Table)
		c.visit(n.Rows)
	case *tree.Update:
		if n.With != nil {
			c.visitCTEs(n.With)
		}
		c.visit(n.Table)
		for _, ue := range n.Exprs {
			c.visit(ue.Expr)
		}
		if n.From != nil {
			for _, t := range n.From {
				c.visit(t)
			}
		}
		if n.Where != nil {
			c.visit(n.Where)
		}
	case *tree.Delete:
		if n.With != nil {
			c.visitCTEs(n.With)
		}
		c.visit(n.Table)
		if n.Where != nil {
			c.visit(n.Where)
		}
	case *tree.DropTable:
		for i := range n.Names {
			c.emitTableName(&n.Names[i])
		}
	case *tree.DropView:
		for i := range n.Names {
			c.emitTableName(&n.Names[i])
		}
	case *tree.DropSequence:
		for i := range n.Names {
			c.emitTableName(&n.Names[i])
		}
	case *tree.AlterTable:
		c.emitTable(unresolvedToString(n.Table))
	case *tree.CreateTable:
		c.emitTableName(&n.Table)
		if n.AsSource != nil {
			c.visit(n.AsSource)
		}
	case *tree.CreateView:
		c.emitTableName(&n.Name)
		if n.AsSource != nil {
			c.visit(n.AsSource)
		}
	case *tree.Truncate:
		for i := range n.Tables {
			c.emitTableName(&n.Tables[i])
		}
	case *tree.CommentOnTable:
		c.emitTable(unresolvedToString(n.Table))
	case *tree.CopyFrom:
		c.emitTableName(&n.Table)
	case *tree.Grant:
		for _, tp := range n.Targets.Tables {
			c.emitTablePattern(tp)
		}
	case *tree.Revoke:
		for _, tp := range n.Targets.Tables {
			c.emitTablePattern(tp)
		}
	case *tree.RenameTable:
		c.visit(n.Name)
		c.visit(n.NewName)
	case *tree.Explain:
		if n.Statement != nil {
			c.visit(n.Statement)
		}

	// ── Table-expression nodes ────────────────────────────────────
	case *tree.From:
		for _, t := range n.Tables {
			c.visit(t)
		}
	case *tree.AliasedTableExpr:
		c.visit(n.Expr)
	case *tree.JoinTableExpr:
		c.visit(n.Left)
		c.visit(n.Right)
		c.visit(n.Cond)
	case *tree.OnJoinCond:
		c.visit(n.Expr)
	case *tree.ParenTableExpr:
		c.visit(n.Expr)
	case *tree.TableName:
		c.emitTableName(n)
	case tree.TableName:
		c.emitTableName(&n)
	case *tree.UnresolvedObjectName:
		c.emitTable(unresolvedToString(n))

	// ── Expressions ───────────────────────────────────────────────
	case tree.SelectExpr:
		c.visit(n.Expr)
	case tree.SelectExprs:
		for _, e := range n {
			c.visit(e)
		}
	case *tree.Where:
		c.visit(n.Expr)
	case *tree.FuncExpr:
		c.emitFunc(n)
		for _, e := range n.Exprs {
			c.visit(e)
		}
		if n.Filter != nil {
			c.visit(n.Filter)
		}
	case *tree.Subquery:
		c.visit(n.Select)
	case *tree.ComparisonExpr:
		c.visit(n.Left)
		c.visit(n.Right)
	case *tree.BinaryExpr:
		c.visit(n.Left)
		c.visit(n.Right)
	case *tree.AndExpr:
		c.visit(n.Left)
		c.visit(n.Right)
	case *tree.OrExpr:
		c.visit(n.Left)
		c.visit(n.Right)
	case *tree.NotExpr:
		c.visit(n.Expr)
	case *tree.ParenExpr:
		c.visit(n.Expr)
	case *tree.CastExpr:
		c.visit(n.Expr)
	case *tree.AnnotateTypeExpr:
		c.visit(n.Expr)
	case *tree.CaseExpr:
		c.visit(n.Expr)
		for _, w := range n.Whens {
			c.visit(w.Cond)
			c.visit(w.Val)
		}
		c.visit(n.Else)
	case *tree.CoalesceExpr:
		for _, e := range n.Exprs {
			c.visit(e)
		}
	case *tree.RangeCond:
		c.visit(n.Left)
		c.visit(n.From)
		c.visit(n.To)
	case *tree.Tuple:
		for _, e := range n.Exprs {
			c.visit(e)
		}
	case *tree.Array:
		for _, e := range n.Exprs {
			c.visit(e)
		}
	case *tree.UnaryExpr:
		c.visit(n.Expr)
	case *tree.ValuesClause:
		for _, row := range n.Rows {
			c.visit(row)
		}
	case tree.Exprs:
		for _, e := range n {
			c.visit(e)
		}
	}
}

// visitCTEs surfaces the inner DML of WITH-CTEs as shadow
// sub-statements (audit §1.2). The outer statement's verb stays
// `with`/`select`/whatever; the inner verb (`delete`, `update`,
// `insert`, `merge`) gets its own pgInfo so a rule keyed on the
// mutating verb fires.
func (c *astCollector) visitCTEs(w *tree.With) {
	for _, cte := range w.CTEList {
		if cte == nil || cte.Stmt == nil {
			continue
		}
		// Each CTE inner is its own logical statement — recurse so
		// nested CTEs surface too.
		switch cte.Stmt.(type) {
		case *tree.Insert, *tree.Update, *tree.Delete:
			info := pgInfo{
				Verb:      strings.ToLower(strings.Fields(cte.Stmt.StatementTag())[0]),
				Statement: tree.AsString(cte.Stmt),
			}
			sub := &astCollector{tables: map[string]struct{}{}, funcs: map[string]struct{}{}}
			sub.visit(cte.Stmt)
			info.Tables = sortedKeys(sub.tables)
			info.Functions = sortedKeys(sub.funcs)
			c.inner = append(c.inner, info)
		}
		// Continue walking the inner so its tables/functions show up
		// in the outer pgInfo too (the regex extractor used to do
		// this, and rules written before the audit may rely on it).
		c.visit(cte.Stmt)
	}
}

func unresolvedToString(u *tree.UnresolvedObjectName) string {
	if u == nil || u.NumParts == 0 {
		return ""
	}
	parts := make([]string, 0, u.NumParts)
	for i := u.NumParts - 1; i >= 0; i-- {
		parts = append(parts, u.Parts[i])
	}
	return strings.Join(parts, ".")
}

func unresolvedNameToString(u *tree.UnresolvedName) string {
	if u == nil || u.NumParts == 0 || u.Star {
		return ""
	}
	parts := make([]string, 0, u.NumParts)
	for i := u.NumParts - 1; i >= 0; i-- {
		parts = append(parts, u.Parts[i])
	}
	return strings.Join(parts, ".")
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── Fallback: verb sniff for parser failures ──────────────────────────
//
// Cockroach's grammar rejects a chunk of postgres-specific syntax:
// LOCK / VACUUM / ANALYZE / REINDEX / REFRESH MATERIALIZED VIEW /
// CLUSTER (§2.1 long tail), SET ROLE / SET SESSION AUTHORIZATION /
// SET LOCAL ROLE (§6.4), DO blocks (§6.5), CALL (§6.6), trailing-`;`
// shells like `DROP;` / `SELECT;` (§1.1). For each piece the parser
// rejected we run a token-driven sniff that surfaces the verb and
// (where it's cheap) the primary table target.

// sniffStmt is the fallback for one parser-rejected statement
// piece. Produces a degraded pgInfo carrying at minimum the verb so
// `verb`-keyed CEL rules keep working.
func sniffStmt(raw string) analysedStmt {
	stmt := strings.TrimSpace(raw)
	info := pgInfo{Statement: stmt}
	if stmt == "" {
		return analysedStmt{Outer: info}
	}
	toks := sniffTokens(stmt)
	if len(toks) == 0 {
		return analysedStmt{Outer: info}
	}
	verb, tables, inner := sniffVerbAndTables(toks)
	info.Verb = verb
	info.Tables = tables
	return analysedStmt{Outer: info, Inner: inner}
}

// sniffVerbAndTables walks a token slice and surfaces:
//   - verb (multi-word forms collapsed for the common identity /
//     identity-adjacent SETs)
//   - tables targeted by the postgres DDL the parser rejects
//   - inner shadow pgInfos for DO blocks (recursively parsed)
func sniffVerbAndTables(toks []sniffTok) (string, []string, []pgInfo) {
	if len(toks) == 0 || toks[0].kind != sniffIdent {
		return "", nil, nil
	}
	v := strings.ToLower(toks[0].val)

	emitNext := func(start int) []string {
		for i := start; i < len(toks); i++ {
			t := toks[i]
			if t.kind == sniffIdent {
				if isSniffNoise(strings.ToLower(t.val)) {
					continue
				}
				return tableCandidates(toks, i)
			}
			if t.kind == sniffQIdent {
				return tableCandidates(toks, i)
			}
		}
		return nil
	}

	switch v {
	case "set":
		// SET ROLE / SET SESSION AUTHORIZATION / SET LOCAL ROLE /
		// SET LOCAL SESSION AUTHORIZATION (audit §6.4). The
		// statement-level identity changes get distinct verbs so a
		// policy can target them without also catching benign
		// session-config SETs.
		if len(toks) >= 2 && toks[1].kind == sniffIdent {
			next := strings.ToLower(toks[1].val)
			switch next {
			case "role":
				return "set role", nil, nil
			case "session":
				if len(toks) >= 3 && toks[2].kind == sniffIdent && strings.ToLower(toks[2].val) == "authorization" {
					return "set session authorization", nil, nil
				}
			case "local":
				if len(toks) >= 3 && toks[2].kind == sniffIdent {
					switch strings.ToLower(toks[2].val) {
					case "role":
						return "set local role", nil, nil
					case "session":
						if len(toks) >= 4 && toks[3].kind == sniffIdent && strings.ToLower(toks[3].val) == "authorization" {
							return "set local session authorization", nil, nil
						}
					}
				}
			}
		}
	case "lock", "vacuum", "analyze", "analyse", "cluster", "reindex":
		return v, emitNext(1), nil
	case "refresh":
		// REFRESH MATERIALIZED VIEW [CONCURRENTLY] x
		i := 1
		if i < len(toks) && toks[i].kind == sniffIdent && strings.ToLower(toks[i].val) == "materialized" {
			i++
		}
		if i < len(toks) && toks[i].kind == sniffIdent && strings.ToLower(toks[i].val) == "view" {
			i++
		}
		return v, emitNext(i), nil
	case "copy":
		// COPY x [(cols)] FROM/TO ... — the parser rejects the
		// file-path / TO stdout forms but the table target is the
		// first identifier after COPY.
		return v, emitNext(1), nil
	case "do":
		// DO $$ ... $$ — the parser rejects DO entirely; we
		// re-tokenise the body and recurse so the inner DROP
		// reaches the matcher (audit §6.5).
		var body string
		for _, t := range toks {
			if t.kind == sniffString {
				body = t.val
				break
			}
		}
		var inner []pgInfo
		if body != "" {
			for _, a := range analyseAll(body) {
				if a.Outer.Verb != "" {
					inner = append(inner, a.Outer)
				}
				inner = append(inner, a.Inner...)
			}
		}
		return v, nil, inner
	case "call":
		return v, nil, nil
	}
	return v, nil, nil
}

// tableCandidates reads a (possibly schema-qualified) name starting
// at toks[i] and returns the qualified + unqualified forms. Quoted
// identifiers preserve case (§2.4).
func tableCandidates(toks []sniffTok, i int) []string {
	if i >= len(toks) {
		return nil
	}
	t := toks[i]
	if t.kind != sniffIdent && t.kind != sniffQIdent {
		return nil
	}
	parts := []string{t.val}
	for j := i + 1; j+1 < len(toks); j += 2 {
		if toks[j].kind != sniffPunct || toks[j].val != "." {
			break
		}
		nxt := toks[j+1]
		if nxt.kind != sniffIdent && nxt.kind != sniffQIdent {
			break
		}
		parts = append(parts, nxt.val)
	}
	full := strings.Join(parts, ".")
	if len(parts) == 1 {
		return []string{full}
	}
	return []string{full, parts[len(parts)-1]}
}

// isSniffNoise returns true for keywords that show up between a
// verb and the table target — TABLE in `LOCK TABLE x`, IF EXISTS in
// `DROP TABLE IF EXISTS x` (parser path), CONCURRENTLY, ONLY.
func isSniffNoise(v string) bool {
	switch v {
	case "table", "index", "view", "if", "exists", "not", "concurrently", "only":
		return true
	}
	return false
}

// ── Tokenizer for the sniff fallback ──────────────────────────────────
//
// Minimal token model — just enough to:
//   - read the first identifier as the verb (skip comments and
//     leading whitespace; trailing `;` does not contaminate it),
//   - read multi-word verb prefixes (SET ROLE, SET SESSION
//     AUTHORIZATION),
//   - capture the table identifier after DDL keywords,
//   - recognise dollar-quoted strings so DO bodies are pulled out
//     intact.

type sniffTokKind int

const (
	sniffIdent  sniffTokKind = iota // unquoted ident (case preserved)
	sniffQIdent                     // quoted ident, case-sensitive
	sniffString                     // string literal — body content only
	sniffPunct                      // one-byte punctuation
	sniffNumber
)

type sniffTok struct {
	kind sniffTokKind
	val  string
}

// sniffTokens is a comment- and string-aware tokeniser for the
// fallback path. Whitespace and comments are dropped; strings carry
// their body text (so DO $$ ... $$ surfaces the inner SQL).
func sniffTokens(s string) []sniffTok {
	var out []sniffTok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			j := i + 2
			for j < len(s) && s[j] != '\n' {
				j++
			}
			i = j
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			depth := 1
			j := i + 2
			for j < len(s) && depth > 0 {
				if j+1 < len(s) && s[j] == '/' && s[j+1] == '*' {
					depth++
					j += 2
				} else if j+1 < len(s) && s[j] == '*' && s[j+1] == '/' {
					depth--
					j += 2
				} else {
					j++
				}
			}
			i = j
		case c == '\'':
			j := i + 1
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			i = j
		case c == '$':
			if tag, end, ok := readDollarQuote(s, i); ok {
				out = append(out, sniffTok{kind: sniffString, val: s[i+len(tag)+2 : end-len(tag)-2]})
				i = end
				continue
			}
			out = append(out, sniffTok{kind: sniffPunct, val: "$"})
			i++
		case c == '"':
			j := i + 1
			var sb strings.Builder
			for j < len(s) {
				if s[j] == '"' {
					if j+1 < len(s) && s[j+1] == '"' {
						sb.WriteByte('"')
						j += 2
						continue
					}
					j++
					break
				}
				sb.WriteByte(s[j])
				j++
			}
			out = append(out, sniffTok{kind: sniffQIdent, val: sb.String()})
			i = j
		case isSniffIdentStart(c):
			j := i + 1
			for j < len(s) && isSniffIdentCont(s[j]) {
				j++
			}
			out = append(out, sniffTok{kind: sniffIdent, val: s[i:j]})
			i = j
		case c >= '0' && c <= '9':
			j := i + 1
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.') {
				j++
			}
			out = append(out, sniffTok{kind: sniffNumber, val: s[i:j]})
			i = j
		default:
			out = append(out, sniffTok{kind: sniffPunct, val: string(c)})
			i++
		}
	}
	return out
}

func isSniffIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 128
}

func isSniffIdentCont(c byte) bool {
	return isSniffIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

// readDollarQuote spots a $tag$ at s[i] and returns (tag, endIdx, true)
// when the matching closing $tag$ is present. End is the byte index
// *after* the closing tag.
func readDollarQuote(s string, i int) (tag string, end int, ok bool) {
	if i >= len(s) || s[i] != '$' {
		return "", 0, false
	}
	j := i + 1
	for j < len(s) && isSniffIdentCont(s[j]) && s[j] != '$' {
		j++
	}
	if j >= len(s) || s[j] != '$' {
		return "", 0, false
	}
	tag = s[i+1 : j]
	openerEnd := j + 1
	closing := "$" + tag + "$"
	idx := strings.Index(s[openerEnd:], closing)
	if idx < 0 {
		// Unterminated dollar-quote — postgres errors here too;
		// treat the rest of the input as the literal body so the
		// extractor can still emit something.
		return tag, len(s), true
	}
	return tag, openerEnd + idx + len(closing), true
}

// splitTopLevelStatements partitions a SQL string at `;` characters
// that aren't inside a string, dollar-quote, comment, or paren
// group. Mirrors the parser's own scanner just well enough that
// `SET ROLE admin; DROP TABLE users` splits even though the parser
// itself rejected the whole input.
func splitTopLevelStatements(s string) []string {
	var out []string
	i, start := 0, 0
	depth := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			j := i + 2
			for j < len(s) && s[j] != '\n' {
				j++
			}
			i = j
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			depthC := 1
			j := i + 2
			for j < len(s) && depthC > 0 {
				if j+1 < len(s) && s[j] == '/' && s[j+1] == '*' {
					depthC++
					j += 2
				} else if j+1 < len(s) && s[j] == '*' && s[j+1] == '/' {
					depthC--
					j += 2
				} else {
					j++
				}
			}
			i = j
		case c == '\'':
			j := i + 1
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			i = j
		case c == '$':
			if _, end, ok := readDollarQuote(s, i); ok {
				i = end
				continue
			}
			i++
		case c == '"':
			j := i + 1
			for j < len(s) {
				if s[j] == '"' {
					if j+1 < len(s) && s[j+1] == '"' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			i = j
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			i++
		case c == ';' && depth == 0:
			piece := strings.TrimSpace(s[start:i])
			if piece != "" {
				out = append(out, piece)
			}
			i++
			start = i
		default:
			i++
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		out = append(out, tail)
	}
	if len(out) == 0 {
		out = append(out, strings.TrimSpace(s))
	}
	return out
}
