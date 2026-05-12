package endpoints

// SQL extractor for the postgres runtime's matcher input.
//
// This is a hand-rolled tokenizer + lightweight walker rather than a
// full Postgres parser — the matcher's predicates are coarse (verb /
// tables / functions / statement glob) so a token-level extraction
// gets the bypass-resistance we need without pulling in a CGO parser
// (deploy builds with CGO_ENABLED=0).
//
// What the lexer handles:
//
//   - '...' / E'...' / U&'...' / B'...' / X'...' strings — opaque
//   - "..." quoted identifiers (preserve contents, lowercase for
//     case-insensitive matching)
//   - $tag$...$tag$ / $$...$$ dollar-quoted strings — opaque
//   - -- line and /* ... */ block comments (block comments nest, per
//     the postgres extension)
//
// What the walker harvests:
//
//   - Verb     — outer verb of the FIRST top-level statement
//                (lowercased; CTE-unwrap: WITH ... <verb> ...
//                surfaces <verb>, not "with")
//   - Verbs    — every top-level statement's outer verb plus every
//                inner verb reachable from WITH ... AS (...)
//                bindings. The plural field lets rule writers match a
//                write hidden after a leading SELECT or inside a CTE.
//   - Tables   — table names following FROM / JOIN / INTO / UPDATE /
//                TABLE / COPY, comma-continued FROM lists, recursive
//                into subqueries and CTE bodies. CTE binding names
//                are filtered out because they refer to the synthetic
//                in-query relation, not a real table.
//   - Functions — every identifier directly preceding an `(` token.
//                 Intentionally overgreedy (the matcher consumes a
//                 list and rule writers query specific names); now
//                 bypass-resistant because strings/comments don't
//                 leak idents into the stream.
//
// What it does NOT do: parse PL/pgSQL bodies inside DO $$...$$ /
// CREATE FUNCTION bodies. Operators who care about those should rule
// on `sql.verb == 'do'` or `'do' in sql.verbs` directly.

import (
	"strings"
)

type pgTokenKind uint8

const (
	pgTokIdent  pgTokenKind = iota // unquoted identifier or keyword
	pgTokQIdent                    // "Quoted Identifier"
	pgTokString                    // '...' / E'...' / $tag$...$tag$ — opaque to extraction
	pgTokPunct                     // ( ) , ;
	pgTokOp                        // operator / number / other char (.= etc.)
)

type pgToken struct {
	kind  pgTokenKind
	value string // original case; for tQIdent, the unescaped contents
	lower string // ASCII-lowercased value; populated only for idents
}

// pgTokenize walks sql char-by-char and emits structured tokens.
// Strings, dollar-quoted strings, and comments are consumed without
// emitting their contents, so identifier-shaped substrings hidden
// inside them cannot leak into table or function extraction.
func pgTokenize(sql string) []pgToken {
	out := make([]pgToken, 0, 32)
	n := len(sql)
	i := 0
	for i < n {
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-':
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			depth := 1
			i += 2
			for i < n && depth > 0 {
				if i+1 < n && sql[i] == '/' && sql[i+1] == '*' {
					depth++
					i += 2
				} else if i+1 < n && sql[i] == '*' && sql[i+1] == '/' {
					depth--
					i += 2
				} else {
					i++
				}
			}
		case c == '\'':
			i = pgScanString(sql, i+1, false)
			out = append(out, pgToken{kind: pgTokString})
		case (c == 'e' || c == 'E') && i+1 < n && sql[i+1] == '\'':
			i = pgScanString(sql, i+2, true)
			out = append(out, pgToken{kind: pgTokString})
		case (c == 'u' || c == 'U') && i+2 < n && sql[i+1] == '&' && sql[i+2] == '\'':
			i = pgScanString(sql, i+3, true)
			out = append(out, pgToken{kind: pgTokString})
		case (c == 'b' || c == 'B' || c == 'x' || c == 'X') && i+1 < n && sql[i+1] == '\'':
			i = pgScanString(sql, i+2, false)
			out = append(out, pgToken{kind: pgTokString})
		case c == '"':
			v, ni := pgScanQuotedIdent(sql, i+1)
			out = append(out, pgToken{kind: pgTokQIdent, value: v, lower: strings.ToLower(v)})
			i = ni
		case c == '$':
			if tag, after, ok := pgScanDollarTag(sql, i); ok {
				closeAt := strings.Index(sql[after:], tag)
				if closeAt < 0 {
					i = n
				} else {
					i = after + closeAt + len(tag)
				}
				out = append(out, pgToken{kind: pgTokString})
			} else {
				// numeric parameter ($1, $2, ...) or stray '$' — opaque
				j := i + 1
				for j < n && sql[j] >= '0' && sql[j] <= '9' {
					j++
				}
				if j == i+1 {
					j++ // stray '$' on its own
				}
				out = append(out, pgToken{kind: pgTokOp, value: sql[i:j]})
				i = j
			}
		case pgIsIdentStart(c):
			j := i + 1
			for j < n && pgIsIdentCont(sql[j]) {
				j++
			}
			v := sql[i:j]
			out = append(out, pgToken{kind: pgTokIdent, value: v, lower: strings.ToLower(v)})
			i = j
		case c == '(' || c == ')' || c == ',' || c == ';':
			out = append(out, pgToken{kind: pgTokPunct, value: string(c)})
			i++
		default:
			out = append(out, pgToken{kind: pgTokOp, value: string(c)})
			i++
		}
	}
	return out
}

// pgScanString advances past a single-quoted string starting at `from`
// (one past the opening apostrophe). Doubled '' is a literal quote
// that does NOT terminate. In E-strings, backslash escapes apply.
// Returns the index just past the terminating apostrophe, or len(sql)
// if the string never closes.
func pgScanString(sql string, from int, eStyle bool) int {
	n := len(sql)
	i := from
	for i < n {
		c := sql[i]
		if eStyle && c == '\\' && i+1 < n {
			i += 2
			continue
		}
		if c == '\'' {
			if i+1 < n && sql[i+1] == '\'' {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return n
}

// pgScanQuotedIdent reads the body of a "..." quoted identifier
// starting one past the opening ". Doubled "" is an embedded quote,
// not a terminator.
func pgScanQuotedIdent(sql string, from int) (string, int) {
	n := len(sql)
	var b strings.Builder
	b.Grow(16)
	i := from
	for i < n {
		c := sql[i]
		if c == '"' {
			if i+1 < n && sql[i+1] == '"' {
				b.WriteByte('"')
				i += 2
				continue
			}
			return b.String(), i + 1
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), n
}

// pgScanDollarTag inspects sql[i:] for a dollar-quote opener.
// Returns the tag ("$tag$" or "$$"), the index just past it, and
// ok=true when one is recognised. Numeric parameter refs ($1, $2...)
// return ok=false.
//
// Tag characters follow Postgres's "unquoted SQL identifier" rule —
// letter/digit/underscore — but NOT '$', because '$' is the tag
// delimiter and including it here would let pgIsIdentCont swallow
// the closing '$'.
func pgScanDollarTag(sql string, i int) (string, int, bool) {
	n := len(sql)
	if i+1 >= n {
		return "", 0, false
	}
	if sql[i+1] == '$' {
		return "$$", i + 2, true
	}
	if !pgIsIdentStart(sql[i+1]) {
		return "", 0, false
	}
	j := i + 1
	for j < n && pgIsTagCont(sql[j]) {
		j++
	}
	if j < n && sql[j] == '$' {
		return sql[i : j+1], j + 1, true
	}
	return "", 0, false
}

func pgIsTagCont(c byte) bool {
	return pgIsIdentStart(c) || (c >= '0' && c <= '9')
}

func pgIsIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func pgIsIdentCont(c byte) bool {
	return pgIsIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

// pgInfo is the structured view of a SQL query fed into the SQL
// matcher.
type pgInfo struct {
	Verb      string
	Verbs     []string // every statement's outer verb + CTE-body verbs
	Tables    []string
	Functions []string
	Statement string
}

// parseSQL extracts verb / verbs / tables / functions / statement for
// the SQL matcher. Replaces the legacy regex extractor whose
// bypasses are catalogued in clawpatrol#143.
func parseSQL(sql string) pgInfo {
	sql = strings.TrimSpace(sql)
	info := pgInfo{Statement: sql}
	if sql == "" {
		return info
	}
	toks := pgTokenize(sql)
	stmts := pgSplitStatements(toks)

	var tables []string
	tableSeen := map[string]bool{}
	addTable := func(name string) {
		if name == "" || tableSeen[name] {
			return
		}
		tableSeen[name] = true
		tables = append(tables, name)
	}

	var functions []string
	funcSeen := map[string]bool{}
	addFunction := func(name string) {
		if name == "" || funcSeen[name] {
			return
		}
		funcSeen[name] = true
		functions = append(functions, name)
	}

	cteNames := map[string]bool{}

	for sidx, stmt := range stmts {
		outer, allVerbs, ctes := pgVerbsAndCTEs(stmt)
		for _, name := range ctes {
			cteNames[name] = true
		}
		if sidx == 0 && outer != "" {
			info.Verb = outer
		}
		for _, v := range allVerbs {
			info.Verbs = appendUnique(info.Verbs, v)
		}
		pgExtractTables(stmt, addTable)
		pgExtractFunctions(stmt, addFunction)
	}

	// CTE binding names shadow real relations only within the query;
	// they shouldn't appear in `tables` because the matcher treats
	// `tables` as "tables this query reads or writes" and a CTE name
	// is a synthetic in-query alias for a sub-result.
	if len(cteNames) > 0 {
		filtered := tables[:0]
		for _, t := range tables {
			if cteNames[t] {
				continue
			}
			filtered = append(filtered, t)
		}
		tables = filtered
	}
	if len(tables) > 0 {
		info.Tables = tables
	}
	if len(functions) > 0 {
		info.Functions = functions
	}
	if len(info.Verbs) == 0 && info.Verb != "" {
		info.Verbs = []string{info.Verb}
	}
	return info
}

func appendUnique(xs []string, v string) []string {
	if v == "" {
		return xs
	}
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

// pgSplitStatements breaks the token stream at top-level (depth-0)
// semicolons. Semicolons inside parens stay attached to the
// surrounding statement.
func pgSplitStatements(toks []pgToken) [][]pgToken {
	var stmts [][]pgToken
	var cur []pgToken
	depth := 0
	for _, t := range toks {
		if t.kind == pgTokPunct {
			switch t.value {
			case "(":
				depth++
			case ")":
				if depth > 0 {
					depth--
				}
			case ";":
				if depth == 0 {
					if len(cur) > 0 {
						stmts = append(stmts, cur)
						cur = nil
					}
					continue
				}
			}
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		stmts = append(stmts, cur)
	}
	return stmts
}

// pgVerbsAndCTEs returns the outer verb of a statement (after
// unwrapping any leading WITH ... AS (...) block), the list of all
// reachable verbs (outer + every CTE-body's verbs, recursively), and
// the list of CTE binding names introduced by the WITH clause.
//
//	WITH RECURSIVE x AS (DELETE FROM secrets RETURNING *) SELECT * FROM x
//	→ outer="select", verbs=["select", "delete"], ctes=["x"]
func pgVerbsAndCTEs(stmt []pgToken) (outer string, verbs []string, ctes []string) {
	i := 0
	if len(stmt) == 0 {
		return "", nil, nil
	}
	if stmt[0].kind == pgTokIdent && stmt[0].lower == "with" {
		i = 1
		if i < len(stmt) && stmt[i].kind == pgTokIdent && stmt[i].lower == "recursive" {
			i++
		}
		for i < len(stmt) {
			if stmt[i].kind != pgTokIdent && stmt[i].kind != pgTokQIdent {
				break
			}
			cteName := stmt[i].lower
			ctes = append(ctes, cteName)
			i++
			// Optional column list
			if i < len(stmt) && stmt[i].kind == pgTokPunct && stmt[i].value == "(" {
				i = pgSkipBalanced(stmt, i)
			}
			// Expect AS
			if i >= len(stmt) || stmt[i].kind != pgTokIdent || stmt[i].lower != "as" {
				break
			}
			i++
			// Optional NOT MATERIALIZED / MATERIALIZED
			if i < len(stmt) && stmt[i].kind == pgTokIdent && stmt[i].lower == "not" {
				i++
			}
			if i < len(stmt) && stmt[i].kind == pgTokIdent && stmt[i].lower == "materialized" {
				i++
			}
			// Expect ( ... )
			if i >= len(stmt) || stmt[i].kind != pgTokPunct || stmt[i].value != "(" {
				break
			}
			start := i + 1
			end := pgSkipBalanced(stmt, i)
			inner := stmt[start : end-1]
			if len(inner) > 0 {
				innerOuter, innerVerbs, innerCTEs := pgVerbsAndCTEs(inner)
				if innerOuter != "" {
					verbs = appendUnique(verbs, innerOuter)
				}
				for _, v := range innerVerbs {
					verbs = appendUnique(verbs, v)
				}
				ctes = append(ctes, innerCTEs...)
			}
			i = end
			if i < len(stmt) && stmt[i].kind == pgTokPunct && stmt[i].value == "," {
				i++
				continue
			}
			break
		}
	}
	for i < len(stmt) {
		if stmt[i].kind == pgTokIdent {
			outer = stmt[i].lower
			break
		}
		i++
	}
	if outer != "" {
		verbs = append([]string{outer}, verbs...)
	}
	return outer, verbs, ctes
}

// pgSkipBalanced consumes a balanced ( ... ) starting at stmt[start]
// (which must be '('). Returns the index just past the matching ')'
// or len(stmt) if the stream is unbalanced.
func pgSkipBalanced(stmt []pgToken, start int) int {
	depth := 0
	for i := start; i < len(stmt); i++ {
		if stmt[i].kind == pgTokPunct {
			switch stmt[i].value {
			case "(":
				depth++
			case ")":
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
	}
	return len(stmt)
}

// Keyword sets used by the FROM-list walker.

// clauseEndKeywords are reserved words that terminate a FROM-style
// table list — once seen (outside of expect-table mode) we stop
// pulling idents as tables.
var clauseEndKeywords = map[string]bool{
	"where": true, "group": true, "order": true, "limit": true,
	"having": true, "union": true, "intersect": true, "except": true,
	"returning": true, "fetch": true, "offset": true, "for": true,
	"window": true, "set": true, "values": true,
	"on": true, "using": true,
	// COPY clause terminators
	"to": true, "from": true, "program": true, "stdin": true, "stdout": true,
}

// joinModifiers are keywords that may appear between table refs in a
// FROM list as part of a JOIN clause. They don't extract tables
// themselves; they sit until JOIN itself appears.
var joinModifiers = map[string]bool{
	"inner": true, "outer": true, "left": true, "right": true,
	"full": true, "cross": true, "natural": true, "lateral": true,
}

// reservedWordsAfterTable are keywords that may appear directly after
// a table name but must NOT be consumed as bare aliases.
var reservedWordsAfterTable = map[string]bool{
	"as": true, "where": true, "group": true, "order": true,
	"limit": true, "having": true, "union": true, "intersect": true,
	"except": true, "returning": true, "fetch": true, "offset": true,
	"for": true, "window": true, "set": true, "values": true,
	"on": true, "using": true, "join": true, "inner": true,
	"outer": true, "left": true, "right": true, "full": true,
	"cross": true, "natural": true, "lateral": true, "to": true,
	"from": true, "program": true, "stdin": true, "stdout": true,
	"with": true, "into": true, "tablesample": true, "table": true,
	"select": true, "delete": true, "update": true, "insert": true,
	"truncate": true, "drop": true, "create": true, "alter": true,
	"copy": true,
}

// tableIntroducer maps a keyword to how it introduces tables:
//
//	"from" — start a FROM clause (comma-list, JOINs, etc.)
//	"one"  — next ident is a single table reference
var tableIntroducer = map[string]string{
	"from":   "from",
	"join":   "one",
	"update": "one",
	"into":   "one",
	"table":  "one",
	"copy":   "one",
}

// pgExtractTables walks the token stream and reports table names via
// emit. Recurses into parenthesised subqueries so writes hidden in a
// subselect still surface.
func pgExtractTables(stmt []pgToken, emit func(string)) {
	pgExtractTablesIn(stmt, emit)
}

func pgExtractTablesIn(stmt []pgToken, emit func(string)) {
	i := 0
	for i < len(stmt) {
		t := stmt[i]
		if t.kind == pgTokPunct && t.value == "(" {
			end := pgSkipBalanced(stmt, i)
			if end > i+1 {
				pgExtractTablesIn(stmt[i+1:end-1], emit)
			}
			i = end
			continue
		}
		if t.kind == pgTokIdent {
			intro, ok := tableIntroducer[t.lower]
			if ok {
				switch intro {
				case "from":
					i = pgConsumeFromList(stmt, i+1, emit)
					continue
				case "one":
					i = pgConsumeTableRef(stmt, i+1, emit, false)
					continue
				}
			}
		}
		i++
	}
}

// pgConsumeFromList scans a FROM clause starting just past the FROM
// keyword. Handles comma-joins, JOIN variants, ON/USING clauses, and
// subquery sources. Returns the index where the FROM clause ended.
func pgConsumeFromList(stmt []pgToken, start int, emit func(string)) int {
	i := start
	expectTable := true
	for i < len(stmt) {
		t := stmt[i]
		switch t.kind {
		case pgTokPunct:
			switch t.value {
			case "(":
				end := pgSkipBalanced(stmt, i)
				if end > i+1 {
					pgExtractTablesIn(stmt[i+1:end-1], emit)
				}
				i = end
				expectTable = false
				continue
			case ",":
				expectTable = true
				i++
				continue
			case ")", ";":
				return i
			default:
				i++
				continue
			}
		case pgTokOp, pgTokString:
			i++
			continue
		case pgTokIdent:
			kw := t.lower
			if !expectTable && clauseEndKeywords[kw] {
				return i
			}
			if kw == "join" {
				expectTable = true
				i++
				continue
			}
			if joinModifiers[kw] {
				i++
				continue
			}
			if kw == "as" {
				i++
				if i < len(stmt) && (stmt[i].kind == pgTokIdent || stmt[i].kind == pgTokQIdent) {
					i++
				}
				expectTable = false
				continue
			}
			if expectTable {
				i = pgConsumeTableRef(stmt, i, emit, true)
				expectTable = false
				continue
			}
			// Out-of-position ident inside a FROM list — likely a
			// bare alias. Consume one token to move on.
			i++
			continue
		case pgTokQIdent:
			if expectTable {
				i = pgConsumeTableRef(stmt, i, emit, true)
				expectTable = false
				continue
			}
			i++
			continue
		default:
			i++
		}
	}
	return i
}

// pgConsumeTableRef reads one table reference at stmt[i] — possibly
// qualified (schema.table), quoted, a function call source, or a
// parenthesised subquery. Skips an optional AS alias / bare alias.
// `insideFromList` toggles bare-alias parsing (a JOIN target uses
// the same rules but only inside a FROM list).
//
// Returns the index just past the reference + alias.
func pgConsumeTableRef(stmt []pgToken, i int, emit func(string), insideFromList bool) int {
	if i >= len(stmt) {
		return i
	}
	t := stmt[i]
	switch t.kind {
	case pgTokPunct:
		if t.value == "(" {
			end := pgSkipBalanced(stmt, i)
			if end > i+1 {
				pgExtractTablesIn(stmt[i+1:end-1], emit)
			}
			i = end
			return pgSkipOptionalAlias(stmt, i, insideFromList)
		}
		return i
	case pgTokQIdent:
		emit(t.lower)
		i++
	case pgTokIdent:
		name := t.lower
		i++
		for i+1 < len(stmt) && stmt[i].kind == pgTokOp && stmt[i].value == "." {
			next := stmt[i+1]
			if next.kind == pgTokIdent || next.kind == pgTokQIdent {
				name = name + "." + next.lower
				i += 2
				continue
			}
			break
		}
		// Table-function source like generate_series(1,10): record
		// the name AND skip the paren'd argument list. Idents inside
		// would still be picked up as functions by the function pass,
		// so we mark the call as the source table only.
		if i < len(stmt) && stmt[i].kind == pgTokPunct && stmt[i].value == "(" {
			emit(name)
			end := pgSkipBalanced(stmt, i)
			i = end
		} else {
			emit(name)
		}
	default:
		i++
		return i
	}
	return pgSkipOptionalAlias(stmt, i, insideFromList)
}

func pgSkipOptionalAlias(stmt []pgToken, i int, insideFromList bool) int {
	if i < len(stmt) && stmt[i].kind == pgTokIdent && stmt[i].lower == "as" {
		i++
		if i < len(stmt) && (stmt[i].kind == pgTokIdent || stmt[i].kind == pgTokQIdent) {
			i++
		}
		return i
	}
	if insideFromList && i < len(stmt) && stmt[i].kind == pgTokIdent && !reservedWordsAfterTable[stmt[i].lower] {
		i++
	}
	return i
}

// pgExtractFunctions reports every identifier directly followed by
// `(`. Overgreedy by design — the matcher consumes a list and rule
// writers query specific names — but now bypass-resistant because
// strings and comments cannot contribute to the token stream.
func pgExtractFunctions(stmt []pgToken, emit func(string)) {
	for i := 0; i+1 < len(stmt); i++ {
		t := stmt[i]
		next := stmt[i+1]
		if t.kind == pgTokIdent && next.kind == pgTokPunct && next.value == "(" {
			emit(t.lower)
		}
	}
}
