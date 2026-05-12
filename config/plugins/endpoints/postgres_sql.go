package endpoints

// SQL extractor for the postgres endpoint. Hand-rolled tokenizer
// (no external parser dependency) — handles comments, quoted
// identifiers, single-quoted and dollar-quoted strings, and
// statement splitting. Replaces the regex-based parseSQL the
// original wire-protocol gateway shipped with.
//
// The audit in denoland/clawpatrol#143 catalogues the regex
// extractor's evasions — comments evading verb capture, CTE-DML
// hidden behind WITH, ;-separated batches showing only the first
// verb, DDL targets invisible to `tables` rules, quoted identifiers
// dropped entirely, DO bodies opaque. All of those collapse onto a
// real tokenizer: once the input is a token stream, the matcher
// input is just a small walk per audit section.
//
// Out of scope for this file: argument-aware function calls
// (§3.4), parameter-value visibility (§4.1 Bind values),
// connection-state identity tracking after SET ROLE (§6.4 runtime
// half — the parser side is here). Those need state the
// stateless extractor doesn't carry.

import (
	"strings"
)

// ── Tokenizer ─────────────────────────────────────────────────────────

type sqlTokKind int

const (
	tokEOF    sqlTokKind = iota
	tokIdent             // unquoted identifier or keyword (lowercased)
	tokQIdent            // quoted identifier (case-preserved)
	tokString            // string literal — single-quoted or dollar-quoted
	tokNumber
	tokPunct // single ASCII punctuation byte
)

// sqlToken is a single lexical element of a SQL statement. val is
// always lowercase for tokIdent (so keyword comparisons are trivial)
// and case-preserved for tokQIdent (postgres treats quoted
// identifiers as case-sensitive). start/end are byte offsets into
// the original source — the per-statement raw text is the source
// slice between the first and last token's start/end.
type sqlToken struct {
	kind  sqlTokKind
	val   string
	start int
	end   int
}

// tokenizeSQL turns raw SQL into a token slice. Whitespace and
// comments are discarded. Unknown bytes become single-char tokPunct
// tokens, so the caller can still see them.
//
// The tokenizer is intentionally postgres-flavoured: dollar-quoted
// strings, E-strings, U&-strings, and nested block comments. It is
// NOT a full SQL parser — no precedence, no AST. It produces a flat
// stream the extractor can sweep over.
func tokenizeSQL(s string) []sqlToken {
	var out []sqlToken
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			// line comment to EOL (or EOF)
			j := i + 2
			for j < len(s) && s[j] != '\n' {
				j++
			}
			i = j
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			// block comment — postgres allows nesting
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
		case c == '\'' || ((c == 'e' || c == 'E') && i+1 < len(s) && s[i+1] == '\''):
			// single-quoted string. E'...' is an escape string; both
			// reach a closing single quote with '' as the only
			// in-string quoting mechanism we model. Backslash escapes
			// in E-strings can shadow a closing quote, but for our
			// extractor's purposes (skip past the literal) treating
			// every \\' inside the literal as escaped is enough.
			tokStart := i
			bodyStart := i
			escape := c != '\''
			if escape {
				bodyStart = i + 1
			}
			j := bodyStart + 1
			for j < len(s) {
				if escape && s[j] == '\\' && j+1 < len(s) {
					j += 2
					continue
				}
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
			out = append(out, sqlToken{kind: tokString, val: s[bodyStart:j], start: tokStart, end: j})
			i = j
		case c == '$':
			// dollar-quoted string: $tag$ ... $tag$ (tag is optional;
			// $$..$$ is valid). The tag is [A-Za-z_][A-Za-z0-9_]*.
			if tag, end, ok := readDollarQuote(s, i); ok {
				out = append(out, sqlToken{kind: tokString, val: s[i+len(tag)+2 : end-len(tag)-2], start: i, end: end})
				i = end
				continue
			}
			// Not a dollar-quoted string — treat $ as punct (e.g., $1
			// parameter reference). The "$1" form falls through into
			// the punct/number tokens which is good enough.
			out = append(out, sqlToken{kind: tokPunct, val: "$", start: i, end: i + 1})
			i++
		case c == '"':
			// quoted identifier — case-preserved, "" is an escaped
			// double-quote inside the name.
			start := i
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
			out = append(out, sqlToken{kind: tokQIdent, val: sb.String(), start: start, end: j})
			i = j
		case isIdentStart(c):
			// Unquoted identifier or keyword.
			start := i
			j := i + 1
			for j < len(s) && isIdentCont(s[j]) {
				j++
			}
			out = append(out, sqlToken{kind: tokIdent, val: strings.ToLower(s[i:j]), start: start, end: j})
			i = j
		case c >= '0' && c <= '9':
			start := i
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			out = append(out, sqlToken{kind: tokNumber, val: s[i:j], start: start, end: j})
			i = j
		default:
			// Single-byte punctuation — covers (, ), ,, ;, ., +, -,
			// *, /, =, <, >, etc. Not meaningfully different from
			// the extractor's perspective.
			out = append(out, sqlToken{kind: tokPunct, val: string(c), start: i, end: i + 1})
			i++
		}
	}
	return out
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 128
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

// readDollarQuote spots a $tag$ at s[i] and returns (tag, endIdx, true)
// when the matching closing $tag$ is present. End is the byte index
// *after* the closing tag.
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
	close := "$" + tag + "$"
	idx := strings.Index(s[openerEnd:], close)
	if idx < 0 {
		// Unterminated dollar-quote — treat as opaque trailing string
		// (matches postgres' parser, which errors).
		return tag, len(s), true
	}
	return tag, openerEnd + idx + len(close), true
}

// ── Statement splitting ───────────────────────────────────────────────

// splitStatements partitions a token stream into top-level
// statements at `;` punctuation. Semicolons inside parentheses are
// not valid SQL at the top level, but we keep them grouped if they
// show up there (defensive).
//
// Returns a slice with at least one entry; empty trailing statements
// (e.g., trailing `;`) are dropped.
func splitStatements(toks []sqlToken) [][]sqlToken {
	if len(toks) == 0 {
		return nil
	}
	var out [][]sqlToken
	var cur []sqlToken
	depth := 0
	for _, t := range toks {
		if t.kind == tokPunct {
			switch t.val {
			case "(":
				depth++
			case ")":
				if depth > 0 {
					depth--
				}
			case ";":
				if depth == 0 {
					if len(cur) > 0 {
						out = append(out, cur)
					}
					cur = nil
					continue
				}
			}
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// ── Extractor ─────────────────────────────────────────────────────────

// analysedStmt is the result of running the extractor over one
// top-level statement. Sub is the per-statement breakdown the
// matcher walks — one entry for the outer statement plus one per
// CTE-hidden DML, DO body statement, and similar.
type analysedStmt struct {
	Outer pgInfo
	Inner []pgInfo
}

// analyseAll tokenises sql, splits into top-level statements,
// extracts pgInfo for each, and returns one analysedStmt per
// statement.
func analyseAll(sql string) []analysedStmt {
	toks := tokenizeSQL(sql)
	stmts := splitStatements(toks)
	if len(stmts) == 0 {
		// Empty input — preserve the legacy behaviour of returning a
		// single pgInfo with Statement="" so dashboard counters don't
		// double-count.
		return []analysedStmt{{Outer: pgInfo{Statement: strings.TrimSpace(sql)}}}
	}
	out := make([]analysedStmt, 0, len(stmts))
	if len(stmts) == 1 {
		out = append(out, analyseOne(stmts[0], strings.TrimSpace(sql)))
		return out
	}
	// Multi-statement: emit per-statement summaries so the dashboard
	// shows each component. The per-statement Statement is the source
	// slice between the first and last token's byte offsets — preserves
	// the operator-typed text including comments and whitespace.
	for _, s := range stmts {
		out = append(out, analyseOne(s, statementText(sql, s)))
	}
	return out
}

// statementText returns the source slice [first.start, last.end]
// trimmed. Empty when toks is empty.
func statementText(src string, toks []sqlToken) string {
	if len(toks) == 0 {
		return ""
	}
	a, b := toks[0].start, toks[len(toks)-1].end
	if a < 0 || a >= len(src) {
		return ""
	}
	if b > len(src) {
		b = len(src)
	}
	return strings.TrimSpace(src[a:b])
}

// analyseOne walks one statement's token stream and returns the
// pgInfo plus any inner shadow statements (CTE DML, DO body).
func analyseOne(toks []sqlToken, raw string) analysedStmt {
	info := pgInfo{Statement: raw}
	if len(toks) == 0 {
		return analysedStmt{Outer: info}
	}
	info.Verb = extractVerb(toks)
	info.Tables = extractTables(toks)
	info.Functions = extractFunctions(toks)

	var inner []pgInfo
	// CTE inner DML (§1.2): walk top-level parens that follow
	// `<ident> AS` after WITH.
	if info.Verb == "with" {
		inner = append(inner, extractCTEInner(toks, raw)...)
	}
	// DO body (§6.5): the dollar-quoted block carries a PL/pgSQL
	// body. We tokenise the body and recurse — the inner statements
	// flow through the matcher as if they had been issued directly.
	if info.Verb == "do" {
		inner = append(inner, extractDOInner(toks)...)
	}
	return analysedStmt{Outer: info, Inner: inner}
}

// extractVerb returns the lowercased verb. Multi-word verbs that
// matter for policy ("set role", "set session authorization", "set
// local role") are surfaced as their joined form so CEL rules can
// distinguish identity changes from session-config SETs (§6.4).
//
// `with` is preserved — the per-CTE inner DML is emitted as a
// separate shadow statement that carries its own verb (§1.2).
func extractVerb(toks []sqlToken) string {
	if len(toks) == 0 {
		return ""
	}
	first := toks[0]
	if first.kind != tokIdent {
		return ""
	}
	v := first.val
	switch v {
	case "set":
		// SET ROLE / SET SESSION AUTHORIZATION / SET LOCAL ROLE /
		// SET LOCAL SESSION AUTHORIZATION.
		if len(toks) >= 2 && toks[1].kind == tokIdent {
			next := toks[1].val
			switch next {
			case "role":
				return "set role"
			case "session":
				if len(toks) >= 3 && toks[2].kind == tokIdent && toks[2].val == "authorization" {
					return "set session authorization"
				}
			case "local":
				if len(toks) >= 3 && toks[2].kind == tokIdent {
					switch toks[2].val {
					case "role":
						return "set local role"
					case "session":
						if len(toks) >= 4 && toks[3].kind == tokIdent && toks[3].val == "authorization" {
							return "set local session authorization"
						}
					}
				}
			}
		}
	}
	return v
}

// extractTables walks the token stream and surfaces table names a
// rule writer would expect to gate on. Compared to the regex-era
// extractor:
//
//   - DDL targets are visible (§2.1): DROP TABLE x, TRUNCATE x,
//     ALTER TABLE x, CREATE TABLE x, GRANT/REVOKE … ON x,
//     LOCK [TABLE] x, VACUUM x, ANALYZE x, REINDEX [TABLE] x,
//     REFRESH MATERIALIZED VIEW x, CLUSTER x, COMMENT ON TABLE x.
//   - COPY targets are visible (§2.2): COPY x FROM/TO …
//   - Schema-qualified names emit both the qualified form and the
//     unqualified leaf (§2.3) so either rule shape catches the read.
//   - Quoted identifiers are captured (§2.4) — case is preserved.
//   - String literals don't produce ghost tables — the tokenizer
//     already strips them from consideration.
func extractTables(toks []sqlToken) []string {
	var out []string
	emit := func(parts []string) {
		if len(parts) == 0 {
			return
		}
		full := strings.Join(parts, ".")
		out = append(out, full)
		if len(parts) > 1 {
			out = append(out, parts[len(parts)-1])
		}
	}
	skipOpts := func(i int) int {
		// Skip optional postgres modifiers that come between a
		// keyword and the table name: ONLY, IF EXISTS, IF NOT EXISTS,
		// CONCURRENTLY.
		for i < len(toks) && toks[i].kind == tokIdent {
			switch toks[i].val {
			case "only", "concurrently":
				i++
			case "if":
				if i+1 < len(toks) && toks[i+1].kind == tokIdent {
					switch toks[i+1].val {
					case "exists":
						i += 2
						continue
					case "not":
						if i+2 < len(toks) && toks[i+2].kind == tokIdent && toks[i+2].val == "exists" {
							i += 3
							continue
						}
					}
				}
				return i
			default:
				return i
			}
		}
		return i
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != tokIdent {
			continue
		}
		switch t.val {
		case "from", "join", "into", "update":
			j := skipOpts(i + 1)
			// Skip LATERAL after JOIN-likes — it's a keyword, not a
			// table (§2.5 FN side).
			if j < len(toks) && toks[j].kind == tokIdent && toks[j].val == "lateral" {
				j++
			}
			emit(readQualifiedName(toks, j))
		case "table":
			// Used after DROP / TRUNCATE / ALTER / CREATE / LOCK /
			// REINDEX / COMMENT ON / etc. — but also as a noise
			// keyword (FOREIGN TABLE, etc.). We capture the next
			// qualified name if it parses.
			emit(readQualifiedName(toks, skipOpts(i+1)))
		case "truncate", "vacuum", "analyze", "analyse", "cluster", "reindex":
			j := skipOpts(i + 1)
			// `TRUNCATE TABLE x` is handled by the "table" branch;
			// `TRUNCATE x` direct form here.
			if j < len(toks) && toks[j].kind == tokIdent && (toks[j].val == "table" || toks[j].val == "index" || toks[j].val == "view" || toks[j].val == "materialized" || toks[j].val == "system" || toks[j].val == "database" || toks[j].val == "schema") {
				continue
			}
			emit(readQualifiedName(toks, j))
		case "refresh":
			// REFRESH MATERIALIZED VIEW [CONCURRENTLY] name
			j := i + 1
			if j < len(toks) && toks[j].kind == tokIdent && toks[j].val == "materialized" {
				j++
				if j < len(toks) && toks[j].kind == tokIdent && toks[j].val == "view" {
					j++
					emit(readQualifiedName(toks, skipOpts(j)))
				}
			}
		case "copy":
			// COPY x (col1,col2) FROM/TO … — x is the table. The
			// regex-era extractor matched FROM and pulled `stdin`;
			// here we pull x.
			emit(readQualifiedName(toks, i+1))
		case "on":
			// GRANT … ON [TABLE] x / COMMENT ON TABLE x / REVOKE …
			// ON [TABLE] x. Bare "ON" without TABLE keyword also
			// works for GRANT ON SCHEMA x — skip those.
			j := i + 1
			if j < len(toks) && toks[j].kind == tokIdent {
				switch toks[j].val {
				case "table":
					emit(readQualifiedName(toks, skipOpts(j+1)))
				}
			}
		}
	}
	return dedupe(out)
}

// readQualifiedName reads a (possibly schema-qualified) identifier
// starting at toks[start]. Returns one entry per dotted component.
// e.g., public.users → ["public", "users"]. "Users" (quoted) →
// ["Users"]. Returns nil when toks[start] isn't an identifier.
func readQualifiedName(toks []sqlToken, start int) []string {
	if start >= len(toks) {
		return nil
	}
	t := toks[start]
	if t.kind != tokIdent && t.kind != tokQIdent {
		return nil
	}
	if t.kind == tokIdent && isReservedTableSpot(t.val) {
		return nil
	}
	parts := []string{t.val}
	for i := start + 1; i+1 < len(toks); i += 2 {
		if toks[i].kind != tokPunct || toks[i].val != "." {
			break
		}
		nxt := toks[i+1]
		if nxt.kind != tokIdent && nxt.kind != tokQIdent {
			break
		}
		parts = append(parts, nxt.val)
	}
	return parts
}

// isReservedTableSpot guards against capturing structural keywords
// that show up where a table would otherwise sit — `SELECT … FROM
// (SELECT …)` shouldn't yield a table named "select", `SELECT … FROM
// LATERAL …` shouldn't yield `lateral`, etc.
func isReservedTableSpot(v string) bool {
	switch v {
	case "select", "values", "lateral", "only", "table":
		return true
	}
	return false
}

func dedupe(xs []string) []string {
	if len(xs) <= 1 {
		return xs
	}
	seen := map[string]struct{}{}
	out := xs[:0]
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// extractFunctions surfaces identifier(callsite tokens. Mirrors the
// regex-era extractor's behaviour for §3.x (out of scope here) but
// is now tokenizer-aware, so string literals no longer produce
// phantom function calls. Schema-qualified callsites surface both
// the full and unqualified forms.
func extractFunctions(toks []sqlToken) []string {
	var out []string
	for i := 0; i+1 < len(toks); i++ {
		t := toks[i]
		if t.kind != tokIdent && t.kind != tokQIdent {
			continue
		}
		if toks[i+1].kind != tokPunct || toks[i+1].val != "(" {
			continue
		}
		// Walk backwards for a possible `schema.` prefix so
		// `pg_catalog.dblink(` captures `pg_catalog.dblink` plus
		// `dblink`.
		parts := []string{t.val}
		for j := i - 2; j >= 0; j -= 2 {
			if toks[j+1].kind != tokPunct || toks[j+1].val != "." {
				break
			}
			if toks[j].kind != tokIdent && toks[j].kind != tokQIdent {
				break
			}
			parts = append([]string{toks[j].val}, parts...)
		}
		out = append(out, strings.Join(parts, "."))
		if len(parts) > 1 {
			out = append(out, parts[len(parts)-1])
		}
	}
	return dedupe(out)
}

// extractCTEInner pulls the inner DML from `WITH x AS (DELETE …
// RETURNING *) SELECT …` style statements. Each parenthesised CTE
// body whose first verb is a mutating statement (INSERT, UPDATE,
// DELETE, MERGE) is surfaced as a shadow statement so the matcher
// sees the inner verb (§1.2).
func extractCTEInner(toks []sqlToken, raw string) []pgInfo {
	var out []pgInfo
	for i := 0; i+2 < len(toks); i++ {
		if toks[i].kind != tokIdent || toks[i].val != "as" {
			continue
		}
		// Find the open paren immediately after AS (possibly with
		// other tokens — column-list aliases like `WITH x(a,b) AS`
		// already had their column list consumed before AS).
		j := i + 1
		if j >= len(toks) || toks[j].kind != tokPunct || toks[j].val != "(" {
			continue
		}
		// Scan until the matching close paren.
		depth := 1
		k := j + 1
		body := []sqlToken{}
		for k < len(toks) && depth > 0 {
			t := toks[k]
			if t.kind == tokPunct {
				if t.val == "(" {
					depth++
				} else if t.val == ")" {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			body = append(body, t)
			k++
		}
		if len(body) == 0 {
			continue
		}
		// Strip leading MATERIALIZED / NOT MATERIALIZED keywords if
		// present (postgres CTE option).
		b := body
		if len(b) > 0 && b[0].kind == tokIdent && b[0].val == "not" {
			b = b[1:]
		}
		if len(b) > 0 && b[0].kind == tokIdent && b[0].val == "materialized" {
			b = b[1:]
		}
		if len(b) == 0 || b[0].kind != tokIdent {
			continue
		}
		verb := b[0].val
		if !isMutatingVerb(verb) {
			continue
		}
		out = append(out, pgInfo{
			Verb:      verb,
			Tables:    extractTables(b),
			Functions: extractFunctions(b),
			Statement: raw, // shadow keeps the outer raw — the
			// dashboard's "statement" filter still sees the original.
		})
	}
	return out
}

// extractDOInner tokenizes the body of a `DO $$ … $$` block and
// returns pgInfo for each inner top-level statement. PL/pgSQL bodies
// can carry arbitrary SQL (`DROP TABLE users` inside `BEGIN … END`);
// the regex extractor saw only the outer DO. (§6.5)
func extractDOInner(toks []sqlToken) []pgInfo {
	// Find the first tokString — that's the body. (DO [LANGUAGE …]
	// $$body$$ — LANGUAGE clause is optional and may come before or
	// after the body.)
	var body string
	for _, t := range toks {
		if t.kind == tokString {
			body = t.val
			break
		}
	}
	if body == "" {
		return nil
	}
	inner := tokenizeSQL(body)
	stmts := splitStatements(inner)
	var out []pgInfo
	for _, s := range stmts {
		if len(s) == 0 {
			continue
		}
		first := s[0]
		if first.kind != tokIdent {
			continue
		}
		// Skip PL/pgSQL keywords that aren't SQL statements per se —
		// BEGIN / END / DECLARE / EXCEPTION blocks. The body still
		// likely contains SQL inside; recurse statement-by-statement
		// past the structural keywords.
		stripped := stripPLpgSQLNoise(s)
		if len(stripped) == 0 || stripped[0].kind != tokIdent {
			continue
		}
		verb := stripped[0].val
		if !isMutatingVerb(verb) && !isReadVerb(verb) {
			continue
		}
		out = append(out, pgInfo{
			Verb:      verb,
			Tables:    extractTables(stripped),
			Functions: extractFunctions(stripped),
			Statement: statementText(body, stripped),
		})
	}
	return out
}

// stripPLpgSQLNoise drops leading PL/pgSQL block keywords (BEGIN,
// END, DECLARE, IF, ELSIF, ELSE, THEN) so the inner statement's verb
// surfaces. Imperfect — PL/pgSQL has loop constructs, RAISE,
// PERFORM, etc. — but the common DO-block evasion shapes the audit
// flagged (`DO $$ BEGIN DROP TABLE users; END $$`) get covered.
func stripPLpgSQLNoise(toks []sqlToken) []sqlToken {
	i := 0
	for i < len(toks) {
		t := toks[i]
		if t.kind == tokPunct {
			i++
			continue
		}
		if t.kind != tokIdent {
			break
		}
		switch t.val {
		case "begin", "end", "declare", "then", "else", "loop", "exception":
			i++
			continue
		case "if", "elsif":
			i++
			continue
		case "perform":
			// PERFORM <expr> runs the expression for side effects;
			// treat as SELECT for visibility.
			i++
			if i < len(toks) {
				return append([]sqlToken{{kind: tokIdent, val: "select"}}, toks[i:]...)
			}
			return nil
		}
		break
	}
	return toks[i:]
}

func isMutatingVerb(v string) bool {
	switch v {
	case "insert", "update", "delete", "merge", "truncate", "drop", "alter", "create", "grant", "revoke", "copy":
		return true
	}
	return false
}

func isReadVerb(v string) bool {
	switch v {
	case "select", "show", "explain", "values", "with", "call":
		return true
	}
	return false
}
