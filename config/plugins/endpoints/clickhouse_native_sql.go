package endpoints

// Best-effort SQL lexer for the clickhouse_native runtime's matcher
// input. The shape mirrors postgres's pgInfo so the SQL family
// matcher consumes both endpoints' output without per-plugin special
// cases.
//
// ClickHouse statements carry a few syntactic trailers postgres
// doesn't have (`SETTINGS k=v, …`, `FORMAT JSON`); stripping them
// before regex extraction keeps `tables` / `function` lists tight
// and makes `statement_regex` rules predictable.

import (
	"regexp"
	"strings"
)

type chSQLInfo struct {
	Verb      string
	Tables    []string
	Functions []string
	Statement string // raw, untrimmed — fed to statement / statement_regex matchers
}

// chSQLTrailerRE strips ClickHouse-specific trailers a query may carry
// after the body proper. Both `SETTINGS …` and `FORMAT …` appear on
// the right side of arbitrary statements (`SELECT … FORMAT JSON`,
// `INSERT … SETTINGS max_insert_threads = 4`), so the lexer treats
// them as optional appendages — chop, then extract verb / tables /
// functions from the prefix.
var chSQLTrailerRE = regexp.MustCompile(`(?is)\s+(?:SETTINGS\s+.*|FORMAT\s+\S+)$`)

var (
	chTableRE = regexp.MustCompile(`(?i)\b(?:from|update|into|join|table)\s+([a-z_][a-z0-9_.]*)`)
	chFuncRE  = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s*\(`)
)

// parseChSQL extracts verb / tables / functions / statement for the
// SQL matcher. Best-effort by design — the matcher's predicates are
// coarse (verb lists, glob'd table names, statement_regex), so a
// regex-based extractor produces actionable results across the v14
// rule shapes without dragging in a full SQL parser.
//
// The raw Statement preserves the original SQL so `statement` /
// `statement_regex` rules see exactly what the agent sent. Verb and
// tables are derived from a trailer-stripped, comment-flattened lower
// case copy.
func parseChSQL(sql string) chSQLInfo {
	info := chSQLInfo{Statement: sql}
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return info
	}
	body := chStripSQLComments(trimmed)
	body = chSQLTrailerRE.ReplaceAllString(body, "")
	body = strings.TrimSpace(body)
	if body == "" {
		return info
	}
	lower := strings.ToLower(body)
	if i := strings.IndexAny(lower, " \t\n\r("); i > 0 {
		info.Verb = lower[:i]
	} else {
		info.Verb = lower
	}
	for _, m := range chTableRE.FindAllStringSubmatch(lower, -1) {
		info.Tables = append(info.Tables, m[1])
	}
	for _, m := range chFuncRE.FindAllStringSubmatch(lower, -1) {
		info.Functions = append(info.Functions, m[1])
	}
	return info
}

// chStripSQLComments removes -- line comments and /* … */ block
// comments. Comments inside quoted string literals are preserved so
// the lexer doesn't accidentally truncate a SQL string that contains
// "--" or "/*".
func chStripSQLComments(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case '\'', '"', '`':
			// Quoted run — copy verbatim, respect doubled-quote escapes.
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
				for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
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
