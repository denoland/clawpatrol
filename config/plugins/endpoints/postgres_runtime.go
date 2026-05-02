package endpoints

// Postgres wire-protocol gateway. The endpoint plugin's
// ConnEndpointRuntime intercepts client→server messages (Query /
// Parse), runs them through the SQL family matcher against the
// endpoint's compiled rules, and either forwards or sends an
// ErrorResponse + ReadyForQuery so the agent can continue with
// another query.
//
// Scope of this iteration:
//
//   - SSLRequest is refused with 'N' (no SSL). Agents must use
//     sslmode=disable or sslmode=prefer; WireGuard already encrypts
//     the tunnel.
//   - StartupMessage + auth flow proxied verbatim — credential
//     plugins implementing PostgresCredentialRuntime swap the agent's
//     password for the real one in a follow-up.
//   - Simple Query ('Q') and Parse ('P') get SQL-parsed.
//     Bind / Execute on prepared statements pass through (Parse
//     captured the SQL already).
//
// Wire format (post-startup):
//
//	[type:1][length:4 BE incl. self][payload: length-4]
//
// StartupMessage / SSLRequest skip the type byte.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/match"
	"github.com/denoland/clawpatrol-go/config/runtime"
)

const sslRequestCode = 80877103

// HandleConn is the postgres ConnEndpointRuntime entry point.
// One call per inbound TCP connection; returns when either side
// closes.
func (PostgresEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer ch.Conn.Close()
	if ch.Endpoint == nil || ch.Endpoint.Family != "sql" {
		return fmt.Errorf("postgres runtime invoked on non-sql endpoint %v", ch.Endpoint)
	}

	upstreamAddr := pgUpstreamAddr(ch.Endpoint)
	if upstreamAddr == "" {
		return fmt.Errorf("postgres endpoint %q has no host", ch.Endpoint.Name)
	}
	upstream, err := ch.DialUpstream(ctx, "tcp", upstreamAddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", upstreamAddr, err)
	}
	defer upstream.Close()

	// SSLRequest peek: 4-byte length + 4-byte code. If it matches,
	// reply 'N' so the agent retries plaintext. Otherwise the bytes
	// we just read are the start of a StartupMessage; forward them.
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(ch.Conn, hdr); err != nil {
		return nil
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	code := binary.BigEndian.Uint32(hdr[4:8])
	if length == 8 && code == sslRequestCode {
		if _, err := ch.Conn.Write([]byte{'N'}); err != nil {
			return nil
		}
		// Next bytes are the real StartupMessage — fall into the loop.
	} else {
		if _, err := upstream.Write(hdr); err != nil {
			return nil
		}
		if length > 8 {
			if _, err := io.CopyN(upstream, ch.Conn, int64(length-8)); err != nil {
				return nil
			}
		}
	}

	// Two pumps: server→client unmodified, client→server with
	// per-message inspection.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(ch.Conn, upstream)
		done <- struct{}{}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		pgClientToServer(ctx, ch, upstream)
	}()
	<-done
	return nil
}

// pgClientToServer pumps the agent's outbound message stream to the
// upstream, inspecting Query / Parse for policy.
func pgClientToServer(ctx context.Context, ch *runtime.ConnHandle, upstream net.Conn) {
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		n, err := ch.Conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				msg, rest, ok := readPgMessage(buf)
				if !ok {
					break
				}
				buf = rest
				if msg.typ == 'Q' || msg.typ == 'P' {
					sql := pgExtractSQL(msg.typ, msg.payload)
					if sql != "" {
						verdict, reason := pgEvaluate(ch, sql)
						if verdict == "deny" {
							pgWriteDeny(ch.Conn, reason)
							log.Printf("pg-deny %s: %s", ch.PeerIP, reason)
							continue
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
	_ = ctx
}

// pgEvaluate runs the SQL through the endpoint's compiled rules and
// returns the disposition for this query.
//
// Returns:
//
//	("deny", reason) — matched rule denies, or approve chain
//	  rejected, or approve chain timed out (host applies its
//	  configured fail mode).
//	("", "")         — no rule fires or the matched rule allows.
func pgEvaluate(ch *runtime.ConnHandle, sql string) (string, string) {
	info := parseSQL(sql)
	mreq := &match.Request{
		Family: "sql",
		SQL: &match.SQLMeta{
			Verb:      info.Verb,
			Tables:    info.Tables,
			Functions: info.Functions,
			Statement: info.Statement,
		},
	}
	cr := runtime.MatchRequest(ch.Endpoint, mreq)
	if cr == nil {
		return "", ""
	}
	summary := pgSummary(info)

	// Approve chain. ConnHandle.Approve dispatches through the
	// host's HITL machinery (same one HTTPS uses) — the postgres
	// runtime pauses on the synchronous return, just like the HTTP
	// path's g.hitl.Wait. nil Approve means HITL isn't wired for
	// this conn family; we default-deny so a misconfigured host
	// can't accidentally let approve-gated queries through.
	if len(cr.Outcome.Approve) > 0 {
		if ch.Approve == nil {
			emit(ch, runtime.ConnEvent{
				Action: "deny", Reason: "HITL not configured",
				Verb: info.Verb, Summary: summary,
			})
			return "deny", "approval required but HITL is not configured"
		}
		v := ch.Approve(runtime.ApproveCallRequest{
			Stages: cr.Outcome.Approve, Verb: info.Verb,
			Summary: summary, Rule: cr,
		})
		if v.Decision != "allow" {
			reason := v.Reason
			if reason == "" {
				reason = "denied by approver"
			}
			emit(ch, runtime.ConnEvent{
				Action: "hitl_deny", Reason: reason,
				Verb: info.Verb, Summary: summary,
			})
			return "deny", reason
		}
		emit(ch, runtime.ConnEvent{
			Action: "hitl_allow", Verb: info.Verb, Summary: summary,
		})
		return "", ""
	}

	if cr.Outcome.Verdict == "deny" {
		reason := cr.Outcome.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		emit(ch, runtime.ConnEvent{
			Action: "deny", Reason: reason,
			Verb: info.Verb, Summary: summary,
		})
		return "deny", reason
	}
	emit(ch, runtime.ConnEvent{
		Action: "allow", Verb: info.Verb, Summary: summary,
	})
	return "", ""
}

func emit(ch *runtime.ConnHandle, ev runtime.ConnEvent) {
	if ch.Emit != nil {
		ch.Emit(ev)
	}
}

func pgWriteDeny(conn net.Conn, reason string) {
	// E (ErrorResponse): S (severity), C (code), M (message), terminator.
	body := []byte("SERROR\x00C42501\x00M" + reason + "\x00\x00")
	msg := append([]byte{'E'}, encUint32(uint32(len(body)+4))...)
	msg = append(msg, body...)
	// Z (ReadyForQuery) — 5 bytes total: 'Z' + length(5) + 'I'.
	ready := []byte{'Z', 0, 0, 0, 5, 'I'}
	_, _ = conn.Write(append(msg, ready...))
}

func pgSummary(info pgInfo) string {
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

func pgUpstreamAddr(ep *config.CompiledEndpoint) string {
	for _, h := range ep.Hosts {
		if h != "" {
			return h
		}
	}
	return ""
}

// ── Wire-protocol framing ─────────────────────────────────────────────

type pgMessage struct {
	typ     byte
	payload []byte
}

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

// ── Best-effort SQL lexer for the SQLMatcher input ────────────────────

type pgInfo struct {
	Verb      string
	Tables    []string
	Functions []string
	Statement string
}

var (
	pgTableRE = regexp.MustCompile(`(?i)\b(?:from|update|into|join)\s+([a-z_][a-z0-9_.]*)`)
	pgFuncRE  = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s*\(`)
)

// parseSQL extracts verb / tables / functions / statement for the
// SQL matcher. Best-effort — a SQL parser would be more correct but
// the matcher's predicates are coarse enough that regex extraction
// produces actionable results for the v14 use cases (banned verbs,
// banned functions, secret-table reads).
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
	for _, m := range pgTableRE.FindAllStringSubmatch(lower, -1) {
		info.Tables = append(info.Tables, m[1])
	}
	for _, m := range pgFuncRE.FindAllStringSubmatch(lower, -1) {
		info.Functions = append(info.Functions, m[1])
	}
	return info
}

// Compile-time interface check — keeps PostgresEndpointRuntime in
// sync with the contract.
var _ runtime.ConnEndpointRuntime = PostgresEndpointRuntime{}
