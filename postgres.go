package main

// Postgres wire-protocol gateway. Inspects client→server messages
// (Query / Parse) at the SQL layer, evaluates them against rules whose
// Match has SQL facets (sql_verb, tables, function, statement,
// statement_regex, account), and either passes them through or sends
// an ErrorResponse + closes the connection.
//
// Scope:
//   - SSLRequest is refused with 'N' (no SSL). Operator's client must
//     use sslmode=disable. WireGuard already encrypts the tunnel.
//   - StartupMessage + Auth flow proxied verbatim (no SCRAM placeholder
//     swap yet — agents authenticate with real credentials).
//   - Simple Query ('Q') and Parse ('P') messages are intercepted and
//     SQL-parsed for the Match facets.
//   - Bind/Execute on prepared statements pass through (Parse already
//     captured the SQL).
//
// Wire format (post-startup):
//   [type:1][length:4 BE incl. self][payload: length-4]
// StartupMessage / SSLRequest skip the type byte.

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

const sslRequestCode = 80877103

// pgInfo is the SQL-side context passed into Match.checkSQL.
type pgInfo struct {
	Verb      string
	Tables    []string
	Function  string
	Statement string
}

func (g *Gateway) handlePostgres(c net.Conn, dstIP string) {
	defer c.Close()
	agentAddr := peerIP(c)
	pip := agentAddr
	profile := g.profileFor(pip)

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(dstIP, "5432"), 10*time.Second)
	if err != nil {
		log.Printf("pg dial %s:5432: %v", dstIP, err)
		return
	}
	defer upstream.Close()

	// Step 1: SSLRequest handshake — peek the first 8 bytes; if it's
	// an SSL-request, refuse with 'N' and let the client retry in
	// plaintext. Otherwise it's a StartupMessage and we forward it.
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	code := binary.BigEndian.Uint32(hdr[4:8])
	if length == 8 && code == sslRequestCode {
		// refuse SSL → 'N'. Client retries with a real StartupMessage
		// (no type byte) which we forward verbatim. Skipping this read
		// would leave StartupMessage bytes in the client→server pump,
		// where readPgMessage misreads them as a typed message and the
		// connection hangs (sslmode=prefer was reproducing this).
		if _, err := c.Write([]byte{'N'}); err != nil {
			return
		}
		startHdr := make([]byte, 8)
		if _, err := io.ReadFull(c, startHdr); err != nil {
			return
		}
		startLen := binary.BigEndian.Uint32(startHdr[:4])
		if _, err := upstream.Write(startHdr); err != nil {
			return
		}
		if startLen > 8 {
			if _, err := io.CopyN(upstream, c, int64(startLen-8)); err != nil {
				return
			}
		}
	} else {
		// hdr is the start of a StartupMessage — forward it before
		// stepping into the message loop.
		if _, err := upstream.Write(hdr); err != nil {
			return
		}
		// remaining StartupMessage payload = length - 8 (we've read 8)
		if length > 8 {
			if _, err := io.CopyN(upstream, c, int64(length-8)); err != nil {
				return
			}
		}
	}

	// From here on it's a regular message stream both ways. We pump
	// server→client unmodified, and client→server with per-message
	// inspection.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(c, upstream)
		done <- struct{}{}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 0, 64*1024)
		tmp := make([]byte, 32*1024)
		for {
			n, err := c.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				for {
					msg, rest, ok := readPgMessage(buf)
					if !ok {
						break
					}
					buf = rest
					// inspect Query / Parse
					if msg.typ == 'Q' || msg.typ == 'P' {
						sql := pgExtractSQL(msg.typ, msg.payload)
						if sql != "" {
							info := parseSQL(sql)
							sample := sql
							if len(sample) > 200 {
								sample = sample[:200]
							}
							ev := Event{
								Mode:    "pg",
								Host:    dstIP,
								AgentIP: agentAddr,
								Method:  strings.ToUpper(info.Verb),
								Path:    sample,
								Action:  "allow",
							}
							if rule := selectPgRule(g.Rules(), pip, profile, info); rule != nil && rule.Action == "deny" {
								reason := rule.Reason
								if reason == "" {
									reason = "denied by policy"
								}
								log.Printf("pg-deny agent=%s verb=%s tables=%v: %s", agentAddr, info.Verb, info.Tables, reason)
								// E (ErrorResponse): S (severity), C (code), M (message), terminator
								errBody := []byte("SERROR\x00C42501\x00M" + denyMessage(reason) + "\x00\x00")
								errMsg := append([]byte{'E'}, encUint32(uint32(len(errBody)+4))...)
								errMsg = append(errMsg, errBody...)
								// Z (ReadyForQuery) — 5 bytes total: 'Z' + length(5) + 'I'
								ready := []byte{'Z', 0, 0, 0, 5, 'I'}
								_, _ = c.Write(append(errMsg, ready...))
								ev.Action = "deny"
								ev.Reason = reason
								ev.Status = 403
								if g.sink != nil {
									g.sink.Emit(ev)
								}
								// keep connection alive — client gets the
								// ErrorResponse + ReadyForQuery and can run
								// more queries.
								continue
							}
							if g.sink != nil {
								g.sink.Emit(ev)
							}
							if g.agents != nil {
								g.agents.trackUA(agentAddr, dstIP, "psql", 0, 0)
							}
						}
					}
					raw := serializePgMessage(msg)
					if _, err := upstream.Write(raw); err != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
}

type pgMessage struct {
	typ     byte
	payload []byte
}

// readPgMessage returns one full message from the head of buf if
// available, plus the remaining bytes.
func readPgMessage(buf []byte) (pgMessage, []byte, bool) {
	if len(buf) < 5 {
		return pgMessage{}, buf, false
	}
	length := binary.BigEndian.Uint32(buf[1:5])
	if length < 4 || int(length)+1 > len(buf) {
		return pgMessage{}, buf, false
	}
	msg := pgMessage{typ: buf[0], payload: buf[5 : 1+length]}
	return msg, buf[1+length:], true
}

func serializePgMessage(m pgMessage) []byte {
	out := make([]byte, 0, 5+len(m.payload))
	out = append(out, m.typ)
	out = append(out, encUint32(uint32(4+len(m.payload)))...)
	out = append(out, m.payload...)
	return out
}

func encUint32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// pgExtractSQL pulls the SQL text out of a Q or P payload. Both end the
// SQL with a NUL terminator.
func pgExtractSQL(typ byte, payload []byte) string {
	switch typ {
	case 'Q':
		return cstring(payload)
	case 'P':
		// P: stmt-name \0  query \0  paramcount(2) ...
		i := indexByte(payload, 0)
		if i < 0 || i+1 >= len(payload) {
			return ""
		}
		return cstring(payload[i+1:])
	}
	return ""
}

func cstring(b []byte) string {
	i := indexByte(b, 0)
	if i < 0 {
		return string(b)
	}
	return string(b[:i])
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// parseSQL is a best-effort lexer for Match.checkSQL. Extracts:
//
//	verb     — first non-whitespace word, lowercased.
//	tables   — names following FROM / UPDATE / INTO / JOIN.
//	function — first function-call identifier (best-effort).
//	statement — original SQL (trimmed) for glob / regex match.
func parseSQL(sql string) pgInfo {
	sql = strings.TrimSpace(sql)
	info := pgInfo{Statement: sql}
	if sql == "" {
		return info
	}
	lower := strings.ToLower(sql)
	if i := strings.IndexAny(lower, " \t\n\r("); i > 0 {
		info.Verb = lower[:i]
	} else {
		info.Verb = lower
	}
	for _, m := range tableRE.FindAllStringSubmatch(lower, -1) {
		info.Tables = append(info.Tables, m[1])
	}
	if m := funcRE.FindStringSubmatch(lower); len(m) > 1 {
		info.Function = m[1]
	}
	return info
}

var (
	tableRE = regexp.MustCompile(`(?i)\b(?:from|update|into|join)\s+([a-z_][a-z0-9_.]*)`)
	funcRE  = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s*\(`)
)

// selectPgRule picks the first rule whose Match has SQL facets that
// satisfy info. Profile + Device scoping mirrors selectHostRule.
func selectPgRule(rules []Rule, peerIP, profile string, info pgInfo) *Rule {
	for _, dev := range []bool{true, false} {
		for i := range rules {
			r := rules[i]
			if r.Profile != "" && r.Profile != profile {
				continue
			}
			if dev {
				if r.Device == "" || r.Device != peerIP {
					continue
				}
			} else if r.Device != "" {
				continue
			}
			if r.Match == nil || !hasSQLFacet(r.Match) {
				continue
			}
			if r.Match.checkSQL(info) {
				return &rules[i]
			}
		}
	}
	return nil
}

func hasSQLFacet(m *Match) bool {
	return len(m.SQLVerb) > 0 || len(m.SQLTables) > 0 || len(m.SQLFunction) > 0 ||
		m.Statement != "" || m.StatementRegex != ""
}

// checkSQL runs only the SQL facets against parsed-query info.
// HTTP / k8s facets are ignored on this path.
func (m *Match) checkSQL(info pgInfo) bool {
	if m == nil {
		return true
	}
	if len(m.SQLVerb) > 0 && !matchSet(m.SQLVerb, info.Verb) {
		return false
	}
	if len(m.SQLTables) > 0 {
		ok := false
		for _, t := range info.Tables {
			if matchSet(m.SQLTables, t) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.SQLFunction) > 0 && !matchSet(m.SQLFunction, info.Function) {
		return false
	}
	if m.Statement != "" {
		if ok, _ := globMatch(m.Statement, info.Statement); !ok {
			return false
		}
	}
	if m.StatementRegex != "" {
		re, err := regexp.Compile(m.StatementRegex)
		if err != nil || !re.MatchString(info.Statement) {
			return false
		}
	}
	return true
}

func globMatch(pat, s string) (bool, error) {
	// Path-style globs aren't a great fit for SQL ("COPY*FROM PROGRAM*").
	// Translate * → .* for substring-style matching.
	rePat := "^" + regexpQuoteWithStarWildcard(pat) + "$"
	re, err := regexp.Compile("(?is)" + rePat)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

func regexpQuoteWithStarWildcard(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '*' {
			b.WriteString(".*")
			continue
		}
		// regexp.QuoteMeta does this for the rest, but inline so we
		// can interleave with * substitution.
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	return b.String()
}

// errPgClosed is a placeholder so the linker doesn't drop fmt.
var _ = fmt.Sprintf
