package endpoints

// SQL extractor for the postgres endpoint's matcher input. Parses
// SQL via pgplex/pgparser (a pure-Go port of postgres' own gram.y
// targeting REL_17_STABLE), walks the AST to harvest tables /
// functions, and derives the verb from each top-level statement
// node. Same shape as clickhouse_native_sql.go so the SQL family
// matcher consumes both endpoints' output without per-plugin
// special cases.
//
// Audit reference: denoland/clawpatrol#143 catalogues the regex
// extractor's evasions. pgplex/pgparser ports postgres' own
// grammar, so the parse-tree path natively covers the full PG
// surface — LOCK / VACUUM / ANALYZE / REINDEX / REFRESH
// MATERIALIZED VIEW / CLUSTER / SET ROLE / SET SESSION
// AUTHORIZATION / DO blocks / CALL all show up as their own AST
// nodes. Comments, strings, dollar quotes, quoted identifiers,
// and ;-separated batches are handled by the lexer.
//
// Fallback path: kicks in only when the parser rejects a piece
// outright (genuine syntax errors, or truncated DDL shells like
// `DROP;` / `SELECT;` that the audit §1.1 cases probe). The
// sniff surfaces the first identifier as the verb so verb-keyed
// CEL rules still fire on malformed input.

import (
	"sort"
	"strings"

	"github.com/pgplex/pgparser/nodes"
	"github.com/pgplex/pgparser/parser"
)

// ── Top-level entry points ────────────────────────────────────────────

// parseSQL extracts a single pgInfo for the first top-level
// statement in sql, plus an unparseable flag mirroring the
// match.Request.Unparseable contract. Used by the ParseStatement
// plugin entry point (action fixtures, dashboard previews). For
// multi-statement payloads the wire-protocol gateway calls
// analyseAll directly so each statement walks the matcher.
//
// Contract (mirrors clickhouse_native's parseChSQL):
//
//   - Parse succeeds → unparseable=false, every facet populated.
//   - Parse fails    → unparseable=true,  only Statement populated
//     (Verb / Tables / Functions left zero). The runtime stashes
//     the flag on match.Request.Unparseable; the matcher marks the
//     unset facets as CEL unknowns and any rule whose condition
//     outcome depends on one synth-denies (fail closed).
//
// No verb-sniffing fallback: any input pgplex refuses (exotic
// syntax, garbled bytes, future shapes the grammar doesn't yet
// handle) goes down the same fail-closed path. That keeps the
// contract operators reason about consistent across query shapes
// and avoids silently-disabled write gates when a sniff happens to
// extract a less-restrictive verb than the real intent.
func parseSQL(sql string) (pgInfo, bool) {
	a := analyseAll(sql)
	if len(a) == 0 {
		return pgInfo{Statement: strings.TrimSpace(sql)}, false
	}
	return a[0].Outer, a[0].Unparseable
}

// analyseAll splits sql into top-level statements and returns one
// analysedStmt per piece. Inner pgInfos surface CTE-hidden DML
// (audit §1.2) and DO block bodies (§6.5) the matcher must see.
//
// We split on top-level `;` first and parse each piece in
// isolation rather than handing the whole batch to parser.Parse —
// pgplex returns bare Stmt nodes (not RawStmt-wrapped) so it
// doesn't carry per-statement byte offsets, and splitting first
// gives us a clean Statement string for each element of a
// multi-statement Q payload.
func analyseAll(sql string) []analysedStmt {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return []analysedStmt{{Outer: pgInfo{}}}
	}
	pieces := splitTopLevelStatements(trimmed)
	out := make([]analysedStmt, 0, len(pieces))
	for _, p := range pieces {
		out = append(out, analysePiece(p))
	}
	return out
}

// analysePiece parses one statement piece and builds its pgInfo.
// Returns Unparseable=true with Statement-only when pgplex refuses
// the piece — the matcher then fails closed on any rule whose CEL
// reads verb / tables / functions for this request.
func analysePiece(sql string) analysedStmt {
	text := strings.TrimSpace(sql)
	if root, err := parser.Parse(text); err == nil && root != nil && len(root.Items) > 0 {
		if stmt := root.Items[0]; stmt != nil {
			return analyseStmt(stmt, text)
		}
	}
	return analysedStmt{Outer: pgInfo{Statement: text}, Unparseable: true}
}

// ── AST walk ──────────────────────────────────────────────────────────

// analyseStmt builds pgInfo from a parsed statement node. `source`
// is the original (untrimmed-of-comments) piece text — used as the
// Statement field so action fixtures / dashboard previews see
// exactly what came off the wire.
func analyseStmt(stmt nodes.Node, source string) analysedStmt {
	info := pgInfo{Statement: source, Verb: verbFromNode(stmt)}
	c := newAstCollector()
	c.visit(stmt)
	info.Tables = sortedKeys(c.tables)
	info.Functions = sortedKeys(c.funcs)
	return analysedStmt{Outer: info, Inner: c.inner}
}

// verbFromNode maps a parsed statement node to the lowercase verb
// the SQL matcher expects. The AST node type carries enough
// information that we don't need string-tag parsing; the exceptions
// are TransactionStmt (BEGIN/COMMIT/ROLLBACK/SAVEPOINT/RELEASE
// share a node) and VariableSetStmt (`SET ROLE` / `SET SESSION
// AUTHORIZATION` get distinct verbs per audit §6.4).
//
// `*nodes.SelectStmt` is reported as "select" even when it carries
// a `WITH` clause whose CTEs mutate — the inner mutation rides on
// astCollector.inner as a shadow statement, matching audit §1.2.
func verbFromNode(stmt nodes.Node) string {
	switch n := stmt.(type) {
	case *nodes.SelectStmt:
		return "select"
	case *nodes.InsertStmt:
		return "insert"
	case *nodes.UpdateStmt:
		return "update"
	case *nodes.DeleteStmt:
		return "delete"
	case *nodes.MergeStmt:
		return "merge"
	case *nodes.CreateStmt, *nodes.ViewStmt, *nodes.IndexStmt,
		*nodes.CreateSeqStmt, *nodes.CreateSchemaStmt,
		*nodes.CreateFunctionStmt, *nodes.CreateTrigStmt,
		*nodes.CreateEnumStmt, *nodes.CreateDomainStmt,
		*nodes.CreateTableAsStmt, *nodes.CreateRoleStmt,
		*nodes.CreatedbStmt:
		return "create"
	case *nodes.DropStmt, *nodes.DropRoleStmt, *nodes.DropdbStmt:
		return "drop"
	case *nodes.AlterTableStmt, *nodes.AlterSeqStmt,
		*nodes.AlterDomainStmt, *nodes.AlterEnumStmt,
		*nodes.AlterRoleStmt, *nodes.AlterRoleSetStmt,
		*nodes.AlterDatabaseStmt, *nodes.AlterDatabaseSetStmt,
		*nodes.AlterObjectSchemaStmt, *nodes.AlterOwnerStmt,
		*nodes.AlterFunctionStmt:
		return "alter"
	case *nodes.RenameStmt:
		return "rename"
	case *nodes.TruncateStmt:
		return "truncate"
	case *nodes.CommentStmt:
		return "comment"
	case *nodes.GrantStmt, *nodes.GrantRoleStmt:
		return "grant"
	case *nodes.CopyStmt:
		return "copy"
	case *nodes.VacuumStmt:
		if !n.IsVacuumCmd {
			return "analyze"
		}
		return "vacuum"
	case *nodes.LockStmt:
		return "lock"
	case *nodes.RefreshMatViewStmt:
		return "refresh"
	case *nodes.ClusterStmt:
		return "cluster"
	case *nodes.ReindexStmt:
		return "reindex"
	case *nodes.DoStmt:
		return "do"
	case *nodes.CallStmt:
		return "call"
	case *nodes.ExplainStmt:
		// Behaviour parity with the previous extractor: the inner
		// statement determines what runs, but the outer verb stays
		// "explain" so a rule that bans EXPLAIN itself still fires.
		return "explain"
	case *nodes.PrepareStmt:
		return "prepare"
	case *nodes.ExecuteStmt:
		return "execute"
	case *nodes.DeallocateStmt:
		return "deallocate"
	case *nodes.DeclareCursorStmt:
		return "declare"
	case *nodes.FetchStmt:
		if n.Ismove {
			return "move"
		}
		return "fetch"
	case *nodes.ClosePortalStmt:
		return "close"
	case *nodes.ListenStmt:
		return "listen"
	case *nodes.UnlistenStmt:
		return "unlisten"
	case *nodes.NotifyStmt:
		return "notify"
	case *nodes.LoadStmt:
		return "load"
	case *nodes.CheckPointStmt:
		return "checkpoint"
	case *nodes.DiscardStmt:
		return "discard"
	case *nodes.ConstraintsSetStmt:
		return "set"
	case *nodes.TransactionStmt:
		return transactionVerb(n)
	case *nodes.VariableSetStmt:
		return variableSetVerb(n)
	case *nodes.VariableShowStmt:
		return "show"
	}
	return ""
}

// transactionVerb maps a TransactionStmt's Kind to the legacy
// matcher vocabulary. BEGIN / START TRANSACTION both surface as
// "begin" (the SQL keyword) so `verb == "begin"` rules don't have
// to fork on synonym.
func transactionVerb(n *nodes.TransactionStmt) string {
	switch n.Kind {
	case nodes.TRANS_STMT_BEGIN, nodes.TRANS_STMT_START:
		return "begin"
	case nodes.TRANS_STMT_COMMIT, nodes.TRANS_STMT_COMMIT_PREPARED:
		return "commit"
	case nodes.TRANS_STMT_ROLLBACK, nodes.TRANS_STMT_ROLLBACK_TO,
		nodes.TRANS_STMT_ROLLBACK_PREPARED:
		return "rollback"
	case nodes.TRANS_STMT_SAVEPOINT:
		return "savepoint"
	case nodes.TRANS_STMT_RELEASE:
		return "release"
	case nodes.TRANS_STMT_PREPARE:
		return "prepare"
	}
	return ""
}

// variableSetVerb mirrors the previous extractor's audit §6.4
// surface for SET — identity changes get distinct multi-word verbs
// so policy can target them without also catching benign
// session-config SETs.
func variableSetVerb(n *nodes.VariableSetStmt) string {
	name := strings.ToLower(n.Name)
	switch name {
	case "role":
		if n.IsLocal {
			return "set local role"
		}
		return "set role"
	case "session_authorization":
		if n.IsLocal {
			return "set local session authorization"
		}
		return "set session authorization"
	}
	return "set"
}

// astCollector walks an AST and records the tables and functions
// it references. Statement-shaped nodes whose target table is in a
// fixed slot (DropStmt.Objects, TruncateStmt.Relations,
// VacuumStmt.Rels, etc.) emit at the case site; expressions
// recurse so subquery / CTE-internal references show up too.
type astCollector struct {
	tables map[string]struct{}
	funcs  map[string]struct{}
	inner  []pgInfo
}

func newAstCollector() *astCollector {
	return &astCollector{
		tables: map[string]struct{}{},
		funcs:  map[string]struct{}{},
	}
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

// emitRangeVar surfaces a *RangeVar (the PG node for any direct
// table reference). Schema-qualified names get both forms via
// emitTable (§2.3). Quoted identifiers are preserved
// case-sensitively because the lexer hands them through Relname
// already unfolded (§2.4).
func (c *astCollector) emitRangeVar(r *nodes.RangeVar) {
	if r == nil || r.Relname == "" {
		return
	}
	if r.Schemaname != "" {
		c.emitTable(r.Schemaname + "." + r.Relname)
	} else {
		c.emitTable(r.Relname)
	}
}

// emitObjectName takes a List of String parts (the shape PG uses
// for DropStmt.Objects / CommentStmt.Object on table-shaped
// objects) and emits the joined name. Quoted identifiers are
// preserved by the lexer in the String values directly.
func (c *astCollector) emitObjectName(list *nodes.List) {
	if list == nil {
		return
	}
	parts := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		if s, ok := it.(*nodes.String); ok {
			parts = append(parts, s.Str)
		}
	}
	if len(parts) == 0 {
		return
	}
	c.emitTable(strings.Join(parts, "."))
}

// funcCallName renders a FuncCall's Funcname list as a
// dot-separated lowercase string. Returns "" when the call is a
// special form we don't surface (e.g. coercion casts that the
// grammar rewrites as FuncCall with an A_Star).
func funcCallName(f *nodes.FuncCall) string {
	if f == nil || f.Funcname == nil {
		return ""
	}
	parts := make([]string, 0, len(f.Funcname.Items))
	for _, it := range f.Funcname.Items {
		if s, ok := it.(*nodes.String); ok {
			parts = append(parts, s.Str)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(strings.Join(parts, "."))
}

func (c *astCollector) emitFunc(f *nodes.FuncCall) {
	name := funcCallName(f)
	if name == "" {
		return
	}
	c.funcs[name] = struct{}{}
	// Mirror table extraction: schema-qualified function names
	// emit the unqualified leaf too so `function == "now"` matches
	// `pg_catalog.now()`.
	if i := strings.LastIndex(name, "."); i >= 0 && i+1 < len(name) {
		c.funcs[name[i+1:]] = struct{}{}
	}
}

// visit is a hand-rolled walker over the pgplex AST. The package
// doesn't ship a generic Walk, so we dispatch by concrete node
// type. Statement-level cases emit target tables at the case site
// and recurse into the substructure that may carry more
// references (subqueries, expressions, CTEs).
func (c *astCollector) visit(node nodes.Node) {
	if node == nil {
		return
	}
	switch n := node.(type) {

	// PG nests lists inside expression slots (ValuesLists is a
	// List of Lists, row constructors carry Lists, etc.). Recurse
	// through them so child nodes still hit the dispatch.
	case *nodes.List:
		c.visitList(n)

	// ── Statement-level dispatch ──────────────────────────────────
	case *nodes.SelectStmt:
		if n.WithClause != nil {
			c.visitCTEs(n.WithClause)
		}
		c.visitList(n.TargetList)
		c.visitList(n.FromClause)
		c.visit(n.WhereClause)
		c.visitList(n.GroupClause)
		c.visit(n.HavingClause)
		c.visitList(n.WindowClause)
		c.visitList(n.ValuesLists)
		c.visitList(n.SortClause)
		c.visit(n.LimitOffset)
		c.visit(n.LimitCount)
		c.visitList(n.LockingClause)
		c.visitList(n.DistinctClause)
		if n.Larg != nil {
			c.visit(n.Larg)
		}
		if n.Rarg != nil {
			c.visit(n.Rarg)
		}

	case *nodes.InsertStmt:
		if n.WithClause != nil {
			c.visitCTEs(n.WithClause)
		}
		c.emitRangeVar(n.Relation)
		c.visit(n.SelectStmt)
		c.visitList(n.ReturningList)

	case *nodes.UpdateStmt:
		if n.WithClause != nil {
			c.visitCTEs(n.WithClause)
		}
		c.emitRangeVar(n.Relation)
		c.visitList(n.TargetList)
		c.visit(n.WhereClause)
		c.visitList(n.FromClause)
		c.visitList(n.ReturningList)

	case *nodes.DeleteStmt:
		if n.WithClause != nil {
			c.visitCTEs(n.WithClause)
		}
		c.emitRangeVar(n.Relation)
		c.visit(n.WhereClause)
		c.visitList(n.UsingClause)
		c.visitList(n.ReturningList)

	case *nodes.MergeStmt:
		if n.WithClause != nil {
			c.visitCTEs(n.WithClause)
		}
		c.emitRangeVar(n.Relation)
		c.visit(n.SourceRelation)
		c.visit(n.JoinCondition)
		c.visitList(n.MergeWhenClauses)
		c.visitList(n.ReturningList)

	// DDL with a single *RangeVar target.
	case *nodes.CreateStmt:
		c.emitRangeVar(n.Relation)
	case *nodes.ViewStmt:
		c.emitRangeVar(n.View)
		c.visit(n.Query)
	case *nodes.AlterTableStmt:
		c.emitRangeVar(n.Relation)
	case *nodes.CopyStmt:
		c.emitRangeVar(n.Relation)
		c.visit(n.Query)
	case *nodes.RefreshMatViewStmt:
		c.emitRangeVar(n.Relation)
	case *nodes.ClusterStmt:
		c.emitRangeVar(n.Relation)
	case *nodes.ReindexStmt:
		c.emitRangeVar(n.Relation)
	case *nodes.LockStmt:
		c.visitList(n.Relations)
	case *nodes.TruncateStmt:
		c.visitList(n.Relations)
	case *nodes.VacuumStmt:
		c.visitList(n.Rels)
	case *nodes.VacuumRelation:
		c.emitRangeVar(n.Relation)
	case *nodes.AlterSeqStmt:
		c.emitRangeVar(n.Sequence)
	case *nodes.CreateSeqStmt:
		c.emitRangeVar(n.Sequence)
	case *nodes.RenameStmt:
		// ALTER TABLE … RENAME, ALTER … RENAME COLUMN, etc. The
		// Relation slot is set for table-shaped objects; for other
		// kinds (constraints, types) it stays nil.
		c.emitRangeVar(n.Relation)
	case *nodes.AlterObjectSchemaStmt:
		c.emitRangeVar(n.Relation)
	case *nodes.AlterOwnerStmt:
		c.emitRangeVar(n.Relation)

	// DDL whose targets are name-lists (DropStmt-style).
	case *nodes.DropStmt:
		if isTableShaped(nodes.ObjectType(n.RemoveType)) {
			for _, it := range listItems(n.Objects) {
				if inner, ok := it.(*nodes.List); ok {
					c.emitObjectName(inner)
				}
			}
		}

	// COMMENT ON TABLE / COMMENT ON COLUMN-on-table.
	case *nodes.CommentStmt:
		if isTableShaped(n.Objtype) {
			if list, ok := n.Object.(*nodes.List); ok {
				c.emitObjectName(list)
			}
		}

	// GRANT/REVOKE on tables.
	case *nodes.GrantStmt:
		if isTableShaped(n.Objtype) {
			for _, it := range listItems(n.Objects) {
				switch obj := it.(type) {
				case *nodes.RangeVar:
					c.emitRangeVar(obj)
				case *nodes.List:
					c.emitObjectName(obj)
				}
			}
		}

	// EXPLAIN <stmt>, PREPARE <name> AS <stmt>, etc. — recurse so
	// the inner statement's tables surface on the outer pgInfo.
	case *nodes.ExplainStmt:
		c.visit(n.Query)
	case *nodes.PrepareStmt:
		c.visit(n.Query)
	case *nodes.DeclareCursorStmt:
		c.visit(n.Query)
	case *nodes.CreateTableAsStmt:
		if n.Into != nil {
			c.emitRangeVar(n.Into.Rel)
		}
		c.visit(n.Query)

	// CALL <proc>(...) — the proc surfaces as a function so
	// `function == "..."` rules still fire (audit §6.6).
	case *nodes.CallStmt:
		if n.Funccall != nil {
			c.visit(n.Funccall)
		}

	// DO $$ ... $$ — re-tokenise and recursively analyse the body
	// so inner DROPs reach the matcher (audit §6.5).
	case *nodes.DoStmt:
		if body := doBody(n); body != "" {
			for _, a := range analyseAll(body) {
				if a.Outer.Verb != "" {
					c.inner = append(c.inner, a.Outer)
				}
				c.inner = append(c.inner, a.Inner...)
			}
		}

	// ── FROM-side nodes ──────────────────────────────────────────
	case *nodes.RangeVar:
		c.emitRangeVar(n)
	case *nodes.JoinExpr:
		c.visit(n.Larg)
		c.visit(n.Rarg)
		c.visit(n.Quals)
	case *nodes.RangeSubselect:
		c.visit(n.Subquery)
	case *nodes.RangeFunction:
		c.visitList(n.Functions)
	case *nodes.RangeTableSample:
		c.visit(n.Relation)
		c.visitList(n.Args)
	case *nodes.FromExpr:
		c.visitList(n.Fromlist)
		c.visit(n.Quals)

	// ── Expression nodes ─────────────────────────────────────────
	case *nodes.ResTarget:
		c.visit(n.Val)
	case *nodes.A_Expr:
		c.visit(n.Lexpr)
		c.visit(n.Rexpr)
	case *nodes.BoolExpr:
		c.visitList(n.Args)
	case *nodes.NullTest:
		c.visit(n.Arg)
	case *nodes.BooleanTest:
		c.visit(n.Arg)
	case *nodes.FuncCall:
		c.emitFunc(n)
		c.visitList(n.Args)
		c.visit(n.AggFilter)
		c.visit(n.Over)
	case *nodes.SubLink:
		c.visit(n.Testexpr)
		c.visit(n.Subselect)
	case *nodes.CaseExpr:
		c.visit(n.Arg)
		c.visitList(n.Args)
		c.visit(n.Defresult)
	case *nodes.CaseWhen:
		c.visit(n.Expr)
		c.visit(n.Result)
	case *nodes.CoalesceExpr:
		c.visitList(n.Args)
	case *nodes.MinMaxExpr:
		c.visitList(n.Args)
	case *nodes.TypeCast:
		c.visit(n.Arg)
	case *nodes.CollateClause:
		c.visit(n.Arg)
	case *nodes.A_Indirection:
		c.visit(n.Arg)
		c.visitList(n.Indirection)
	case *nodes.A_ArrayExpr:
		c.visitList(n.Elements)
	case *nodes.RowExpr:
		c.visitList(n.Args)
	case *nodes.NamedArgExpr:
		c.visit(n.Arg)
	case *nodes.SortBy:
		c.visit(n.Node)
	case *nodes.WindowDef:
		c.visitList(n.PartitionClause)
		c.visitList(n.OrderClause)
	case *nodes.LockingClause:
		c.visitList(n.LockedRels)
	}
}

// visitList walks a *nodes.List, recursing into each item.
// Safely handles nil — pgplex uses nil to mean "absent list".
func (c *astCollector) visitList(list *nodes.List) {
	if list == nil {
		return
	}
	for _, it := range list.Items {
		c.visit(it)
	}
}

// visitCTEs surfaces the inner DML of WITH-CTEs as shadow
// sub-statements (audit §1.2). The outer statement's verb stays
// `select` / whatever; the inner verb (`delete`, `update`,
// `insert`, `merge`) gets its own pgInfo so a rule keyed on the
// mutating verb fires.
func (c *astCollector) visitCTEs(w *nodes.WithClause) {
	if w == nil || w.Ctes == nil {
		return
	}
	for _, it := range w.Ctes.Items {
		cte, ok := it.(*nodes.CommonTableExpr)
		if !ok || cte == nil || cte.Ctequery == nil {
			continue
		}
		switch cte.Ctequery.(type) {
		case *nodes.InsertStmt, *nodes.UpdateStmt,
			*nodes.DeleteStmt, *nodes.MergeStmt:
			info := pgInfo{
				Verb:      verbFromNode(cte.Ctequery),
				Statement: cte.Ctename,
			}
			sub := newAstCollector()
			sub.visit(cte.Ctequery)
			info.Tables = sortedKeys(sub.tables)
			info.Functions = sortedKeys(sub.funcs)
			c.inner = append(c.inner, info)
		}
		// Continue walking the inner so its tables / functions show
		// up in the outer pgInfo too (rules written before the
		// audit may rely on this — the regex extractor used to do
		// it).
		c.visit(cte.Ctequery)
	}
}

// listItems returns the list's items, or nil for a nil list. The
// helper lets the visit switch read uniformly without nil checks
// at every list-typed Objects field.
func listItems(l *nodes.List) []nodes.Node {
	if l == nil {
		return nil
	}
	return l.Items
}

// isTableShaped reports whether an ObjectType refers to a
// table-shaped object (table / view / matview / sequence /
// foreign table). DropStmt / CommentStmt / GrantStmt all share the
// ObjectType enum so we centralise the check here.
func isTableShaped(t nodes.ObjectType) bool {
	switch t {
	case nodes.OBJECT_TABLE, nodes.OBJECT_VIEW,
		nodes.OBJECT_MATVIEW, nodes.OBJECT_SEQUENCE,
		nodes.OBJECT_FOREIGN_TABLE:
		return true
	}
	return false
}

// doBody extracts the BODY of a DO $$ … $$ block. The body lives
// in a DefElem named "as" whose Arg is a *String. Returns "" when
// the DO carries no body (unparseable input).
func doBody(d *nodes.DoStmt) string {
	if d == nil || d.Args == nil {
		return ""
	}
	for _, it := range d.Args.Items {
		de, ok := it.(*nodes.DefElem)
		if !ok || de == nil {
			continue
		}
		if strings.EqualFold(de.Defname, "as") {
			if s, ok := de.Arg.(*nodes.String); ok {
				return s.Str
			}
		}
	}
	return ""
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

// ── Statement-split helpers ───────────────────────────────────────────
//
// splitTopLevelStatements needs to be comment- / string- /
// dollar-quote-aware so a `;` inside `'foo;bar'` or `$$DELETE;$$`
// doesn't fracture a single statement into two pieces; readDollarQuote
// + the ident classifiers are the lexer primitives that supports.
// Kept after sniff went away because the splitter still needs them.

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 128
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

// readDollarQuote spots a $tag$ at s[i] and returns
// (tag, endIdx, true) when the matching closing $tag$ is present.
// End is the byte index *after* the closing tag.
func readDollarQuote(s string, i int) (tag string, end int, ok bool) {
	if i >= len(s) || s[i] != '$' {
		return "", 0, false
	}
	j := i + 1
	for j < len(s) && isIdentCont(s[j]) && s[j] != '$' {
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

// splitTopLevelStatements partitions a SQL string at `;`
// characters that aren't inside a string, dollar-quote, comment,
// or paren group. Mirrors the parser's own scanner just well
// enough that `SET ROLE admin; DROP TABLE users` splits even when
// the parser itself rejected the whole input.
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
