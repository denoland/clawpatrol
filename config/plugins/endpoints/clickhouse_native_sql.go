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

// chCTEInsertTargetRE captures the target table (and skips an optional
// column list) of an `INSERT INTO X [(cols)]` clause. Anchored, since
// the CTE+INSERT rewrite path calls it on a substring that begins at
// the INSERT keyword position located by chFindTopLevelKeyword.
var chCTEInsertTargetRE = regexp.MustCompile(`(?is)^INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_.]*)\s*(?:\([^)]*\))?\s*`)

type chSQLInfo struct {
	Verb      string
	Tables    []string
	Functions []string
	Statement string // raw, untrimmed — fed to statement / statement_regex matchers
}

// parseChSQL extracts verb / tables / functions / statement for the
// SQL matcher.
//
// On parser failure we fall back to a degraded `chSQLInfo` carrying
// only `Statement` plus a best-effort verb sniffed from the first
// keyword. Forwarding `Statement` keeps `statement_regex` rules live
// even on syntactically odd inputs the AST parser rejects, which
// matters because those are exactly the queries an operator most
// likely wants to match on.
func parseChSQL(sql string) chSQLInfo {
	info := chSQLInfo{Statement: sql}
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return info
	}

	parseInput := chSQLTrailerRE.ReplaceAllString(trimmed, "")
	stmts, err := chparser.NewParser(parseInput).ParseStmts()
	if err != nil || len(stmts) == 0 {
		// AfterShip's parser refuses CTE-prefixed INSERTs
		// (`WITH … INSERT INTO X SELECT …`), which are routine in
		// ClickHouse analytics workloads. Detect that shape, strip
		// the `INSERT INTO X [(cols)]` clause, and parse the
		// residual `WITH … SELECT …`. We then graft the INSERT
		// target onto the table set and pin the verb explicitly.
		if rewritten, target, ok := chRewriteCTEInsert(parseInput); ok {
			if rstmts, rerr := chparser.NewParser(rewritten).ParseStmts(); rerr == nil && len(rstmts) > 0 {
				tables, funcs := chWalkSQL(rstmts)
				if target != "" {
					tables[strings.ToLower(target)] = struct{}{}
				}
				info.Verb = "insert"
				info.Tables = chSortedKeys(tables)
				info.Functions = chSortedKeys(funcs)
				return info
			}
		}
		info.Verb = chSniffVerb(trimmed)
		return info
	}

	// Multi-statement queries: the verb tracks the first statement, but
	// tables / functions are unioned across all of them so a rule that
	// denies access to `secrets` still fires when `secrets` is the
	// second statement in a "use db; select * from secrets" pair.
	info.Verb = chVerbFromStmt(stmts[0])
	tables, funcs := chWalkSQL(stmts)
	info.Tables = chSortedKeys(tables)
	info.Functions = chSortedKeys(funcs)
	return info
}

// chWalkSQL walks every AST in stmts and collects the table refs and
// function names the SQL matcher cares about. Pulled out so the CTE+INSERT
// rewrite path doesn't have to duplicate the visitor.
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

// chRewriteCTEInsert detects the `WITH … INSERT INTO X [(cols)] SELECT …`
// shape (CTE-prefixed INSERT) and returns a parseable substitute that drops
// just the `INSERT INTO X [(cols)]` clause, leaving the WITH block and the
// trailing SELECT behind. Plus the captured target table.
//
// AfterShip's parser supports `WITH … SELECT …` and standalone
// `INSERT … SELECT …` but not the union of the two; this rewrite is the
// minimal transformation that lets the existing AST walker pull functions
// and source tables out of the body while the caller patches the verb to
// "insert" and adds the target.
//
// Returns ok=false when the input doesn't begin with WITH or no top-level
// INSERT keyword can be located — in which case the caller falls through
// to the verb-sniffing fallback.
func chRewriteCTEInsert(sql string) (rewritten, target string, ok bool) {
	if !chBeginsWithKeyword(sql, "WITH") {
		return "", "", false
	}
	pos := chFindTopLevelKeyword(sql, "INSERT")
	if pos < 0 {
		return "", "", false
	}
	m := chCTEInsertTargetRE.FindStringSubmatchIndex(sql[pos:])
	if m == nil {
		return "", "", false
	}
	target = sql[pos+m[2] : pos+m[3]]
	rewritten = sql[:pos] + sql[pos+m[1]:]
	return rewritten, target, true
}

// chIsSQLWordChar reports whether c is part of a SQL identifier / keyword
// token under the lexer's word-boundary rules. Kept narrow on purpose:
// only ASCII alphanumerics and underscore — matches the keyword scanner's
// expectations and avoids surprises on UTF-8 multibyte sequences.
func chIsSQLWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

// chBeginsWithKeyword reports whether s starts with the SQL keyword kw,
// skipping leading whitespace and SQL comments and requiring a word
// boundary after the match. Case-insensitive. Used to guard the CTE+INSERT
// rewrite to inputs that actually open with `WITH`, since rewriting any
// parse failure that contains an INSERT keyword would corrupt unrelated
// statements (e.g. `SELECT 1; INSERT INTO x VALUES (1)` should not become
// `SELECT 1;` plus a phantom target).
func chBeginsWithKeyword(s, kw string) bool {
	i := chSkipWhitespaceAndComments(s, 0)
	if i+len(kw) > len(s) {
		return false
	}
	if !strings.EqualFold(s[i:i+len(kw)], kw) {
		return false
	}
	if after := i + len(kw); after < len(s) && chIsSQLWordChar(s[after]) {
		return false
	}
	return true
}

// chFindTopLevelKeyword returns the byte index of the first occurrence
// of kw in s that sits at parenthesis depth zero and outside string
// literals or SQL comments, with word boundaries on both sides.
// Case-insensitive. Returns -1 if no such occurrence exists.
//
// Used by the CTE+INSERT rewrite to find the INSERT keyword that ends
// the WITH block. A naive substring search would mis-fire on
// `WITH x AS (SELECT 'INSERT INTO …') …` (string literal) or on
// `WITH x AS (INSERT INTO …) …` (nested DML, paren depth > 0).
func chFindTopLevelKeyword(s, kw string) int {
	depth := 0
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			q := c
			i++
			for i < len(s) {
				ch := s[i]
				i++
				if ch == q {
					if i < len(s) && s[i] == q {
						i++ // doubled-quote escape inside a literal
						continue
					}
					break
				}
				if ch == '\\' && i < len(s) {
					i++ // backslash escape (single-quoted strings)
				}
			}
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			i += 2
			for i+1 < len(s) && (s[i] != '*' || s[i+1] != '/') {
				i++
			}
			if i+1 < len(s) {
				i += 2
			} else {
				i = len(s)
			}
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			i++
		case depth == 0 && chIsSQLWordChar(c) && (i == 0 || !chIsSQLWordChar(s[i-1])):
			if i+len(kw) <= len(s) &&
				strings.EqualFold(s[i:i+len(kw)], kw) &&
				(i+len(kw) == len(s) || !chIsSQLWordChar(s[i+len(kw)])) {
				return i
			}
			for i < len(s) && chIsSQLWordChar(s[i]) {
				i++
			}
		default:
			i++
		}
	}
	return -1
}

// chSkipWhitespaceAndComments advances past ASCII whitespace and SQL
// comments (`-- line` and `/* block */`) starting at i and returns the
// next significant byte's index. Bounded by len(s).
func chSkipWhitespaceAndComments(s string, i int) int {
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			i += 2
			for i+1 < len(s) && (s[i] != '*' || s[i+1] != '/') {
				i++
			}
			if i+1 < len(s) {
				i += 2
			} else {
				i = len(s)
			}
		default:
			return i
		}
	}
	return i
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

// chSniffVerb is the parser-failure fallback: lowercase the first
// alphabetic run and return it. Keeps `verb=` rules functional when
// the AST parser bails — at the cost of correctness on exotic syntax,
// which the matcher would have struggled with anyway.
func chSniffVerb(s string) string {
	body := chStripSQLComments(s)
	body = strings.TrimSpace(body)
	for i := 0; i < len(body); i++ {
		c := body[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isLetter {
			continue
		}
		j := i
		for j < len(body) {
			cj := body[j]
			isAlnum := (cj >= 'a' && cj <= 'z') || (cj >= 'A' && cj <= 'Z') || (cj >= '0' && cj <= '9') || cj == '_'
			if !isAlnum {
				break
			}
			j++
		}
		return strings.ToLower(body[i:j])
	}
	return ""
}

// chStripSQLComments removes -- line comments and /* … */ block
// comments. Comments inside quoted string literals are preserved so
// the lexer doesn't accidentally truncate a SQL string that contains
// "--" or "/*". Used by the parser-failure fallback path.
func chStripSQLComments(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case '\'', '"', '`':
			q := c
			out.WriteByte(c)
			i++
			for i < len(s) {
				ch := s[i]
				out.WriteByte(ch)
				i++
				if ch == q {
					if i < len(s) && s[i] == q {
						out.WriteByte(s[i])
						i++
						continue
					}
					break
				}
			}
		case '-':
			if i+1 < len(s) && s[i+1] == '-' {
				for i < len(s) && s[i] != '\n' {
					i++
				}
				continue
			}
			out.WriteByte(c)
			i++
		case '/':
			if i+1 < len(s) && s[i+1] == '*' {
				i += 2
				for i+1 < len(s) && (s[i] != '*' || s[i+1] != '/') {
					i++
				}
				if i+1 < len(s) {
					i += 2
				} else {
					i = len(s)
				}
				out.WriteByte(' ')
				continue
			}
			out.WriteByte(c)
			i++
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
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
	parts := []string{strings.ToUpper(info.Verb)}
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
