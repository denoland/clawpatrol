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
//
// Flow:
//
//  1. SSLRequest from agent → reply 'N' (refuse TLS, WG already
//     encrypts).
//  2. Read agent's StartupMessage; extract `database` for upstream.
//  3. Resolve credential, get (user, password) via PostgresAuthCredential.
//  4. Dial upstream, send our own StartupMessage(real_user, database).
//  5. Drive upstream auth (SCRAM-SHA-256 or cleartext) using real
//     password. Buffer post-auth frames (ParameterStatus*,
//     BackendKeyData, ReadyForQuery).
//  6. Synthesize AuthenticationOk to agent + replay buffered
//     post-auth frames so agent proceeds as if it just authed.
//  7. Bidirectional pump with per-query inspection.
func (PostgresEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer ch.Conn.Close()
	if ch.Endpoint == nil || ch.Endpoint.Family != "sql" {
		return fmt.Errorf("postgres runtime invoked on non-sql endpoint %v", ch.Endpoint)
	}

	upstreamAddr := pgUpstreamAddr(ch.Endpoint)
	if upstreamAddr == "" {
		return fmt.Errorf("postgres endpoint %q has no host", ch.Endpoint.Name)
	}

	// Step 1: agent's first 8 bytes — SSLRequest or StartupMessage.
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(ch.Conn, hdr); err != nil {
		return nil
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	code := binary.BigEndian.Uint32(hdr[4:8])
	var startupHead []byte
	if length == 8 && code == sslRequestCode {
		if _, err := ch.Conn.Write([]byte{'N'}); err != nil {
			return nil
		}
		startupHead = nil
	} else {
		startupHead = hdr // actually the start of the StartupMessage
	}

	// Step 2: read full StartupMessage from agent.
	startupBody, err := pgReadStartup(ch.Conn, startupHead)
	if err != nil {
		return fmt.Errorf("read agent startup: %w", err)
	}
	database := pgStartupParam(startupBody, "database")
	if database == "" {
		database = pgStartupParam(startupBody, "user") // pg default
	}

	// Step 3: resolve credential. Multi-credential postgres endpoints
	// (account ro/rw) dispatch on the placeholder string the agent
	// embedded in the StartupMessage user field — operator sets
	// PGUSER=PH_pg_deployng_ro and the gateway picks the matching
	// credential. Single-credential endpoints fall through to the
	// only entry.
	agentUser := pgStartupParam(startupBody, "user")
	cc := pgResolveCredential(ch.Endpoint, agentUser)
	if cc == nil {
		pgWriteError(ch.Conn, "no credential bound to postgres endpoint")
		return fmt.Errorf("no credential")
	}
	// Plugin.Runtime is a typed-nil sentinel used for interface
	// dispatch checks; the actual decoded HCL value is on Body.
	auth, ok := cc.Credential.Body.(runtime.PostgresAuthCredential)
	if !ok {
		pgWriteError(ch.Conn, "credential plugin does not implement postgres auth")
		return fmt.Errorf("credential %q has no PostgresAuth", cc.Credential.Symbol.Name)
	}
	sec, err := ch.Secrets.Get(cc.Credential.Symbol.Name, ch.Profile)
	if err != nil {
		pgWriteError(ch.Conn, "fetch secret: "+err.Error())
		return err
	}
	realUser, realPassword := auth.PostgresAuth(sec)
	if realUser == "" {
		pgWriteError(ch.Conn, "postgres credential has no user — set `user = ...` in HCL")
		return fmt.Errorf("credential %q missing user", cc.Credential.Symbol.Name)
	}
	if realPassword == "" {
		pgWriteError(ch.Conn, fmt.Sprintf("postgres credential %q has no password — paste it via the dashboard", cc.Credential.Symbol.Name))
		return fmt.Errorf("credential %q missing password", cc.Credential.Symbol.Name)
	}

	// Step 4: dial upstream, optionally negotiate TLS, then send our
	// own StartupMessage with real (user, database).
	upstream, err := ch.DialUpstream(ctx, "tcp", upstreamAddr)
	if err != nil {
		pgWriteError(ch.Conn, "dial upstream: "+err.Error())
		return fmt.Errorf("dial %s: %w", upstreamAddr, err)
	}
	defer upstream.Close()

	pgEp, _ := ch.Endpoint.Body.(*PostgresEndpoint)
	sslmode := "prefer"
	if pgEp != nil && pgEp.SSLMode != "" {
		sslmode = pgEp.SSLMode
	}
	if sslmode != "disable" {
		secured, sslErr := pgUpgradeSSL(upstream, pgEp, sslmode)
		if sslErr != nil {
			pgWriteError(ch.Conn, "upstream tls: "+sslErr.Error())
			return sslErr
		}
		if secured != nil {
			upstream = secured
		}
	}

	if err := pgSendStartup(upstream, realUser, database); err != nil {
		pgWriteError(ch.Conn, "send upstream startup: "+err.Error())
		return err
	}

	// Step 5 + 6: drive upstream auth, replay post-auth to agent.
	postAuth, err := pgPerformAuth(upstream, realUser, realPassword)
	if err != nil {
		pgWriteError(ch.Conn, "upstream auth: "+err.Error())
		return err
	}
	if err := pgWriteAuthOK(ch.Conn, postAuth); err != nil {
		return nil
	}

	// Step 7: bidirectional pump with per-query inspection. The
	// picked credential's bare name flows into match.Request.Credential
	// so SQL rules with `match = { credential = pg-deployng-ro }`
	// resolve against the right account.
	credName := cc.Credential.Symbol.Name
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(ch.Conn, upstream)
		done <- struct{}{}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		pgClientToServer(ctx, ch, upstream, credName)
	}()
	<-done
	return nil
}

// pgReadStartup reads the rest of a StartupMessage given the first 8
// bytes already pulled off the wire. The first 4 bytes are length;
// payload is length-4 bytes total (the 8-byte head includes 4 bytes
// of payload — typically the protocol version 196608).
func pgReadStartup(r io.Reader, head []byte) ([]byte, error) {
	if head == nil {
		head = make([]byte, 8)
		if _, err := io.ReadFull(r, head); err != nil {
			return nil, err
		}
	}
	length := binary.BigEndian.Uint32(head[:4])
	if length < 8 || length > 1<<20 {
		return nil, fmt.Errorf("bogus startup length %d", length)
	}
	out := make([]byte, length)
	copy(out, head)
	rest := length - 8
	if rest > 0 {
		if _, err := io.ReadFull(r, out[8:]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// pgStartupParam pulls one named parameter out of a StartupMessage
// body. Params start at offset 8 (after length + protocol version),
// alternating null-terminated key/value strings, terminated by an
// extra null byte.
func pgStartupParam(body []byte, key string) string {
	if len(body) < 8 {
		return ""
	}
	b := body[8:]
	for len(b) > 0 && b[0] != 0 {
		end := 0
		for end < len(b) && b[end] != 0 {
			end++
		}
		k := string(b[:end])
		if end+1 > len(b) {
			break
		}
		b = b[end+1:]
		end = 0
		for end < len(b) && b[end] != 0 {
			end++
		}
		v := string(b[:end])
		if end+1 > len(b) {
			break
		}
		b = b[end+1:]
		if k == key {
			return v
		}
	}
	return ""
}

// pgClientToServer pumps the agent's outbound message stream to the
// upstream, inspecting Query / Parse for policy.
func pgClientToServer(ctx context.Context, ch *runtime.ConnHandle, upstream net.Conn, credName string) {
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
						verdict, reason := pgEvaluate(ch, sql, credName)
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
func pgEvaluate(ch *runtime.ConnHandle, sql, credName string) (string, string) {
	info := parseSQL(sql)
	mreq := &match.Request{
		Family:     "sql",
		PeerIP:     ch.PeerIP,
		Credential: credName,
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

// pgResolveCredential picks the credential entry for this connection.
//
// Single-binding endpoints (one entry, no placeholder) return that
// entry. Multi-credential endpoints dispatch on the agent-supplied
// StartupMessage user field — exact match against each entry's
// placeholder. Trailing no-placeholder entry is the fallback when no
// placeholder matched.
//
// Returns nil only when the endpoint declared zero credentials.
func pgResolveCredential(ep *config.CompiledEndpoint, agentUser string) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	if len(ep.Credentials) == 1 && ep.Credentials[0].Placeholder == "" {
		return ep.Credentials[0]
	}
	var fallback *config.CompiledCredential
	for _, c := range ep.Credentials {
		if c.Placeholder == "" {
			fallback = c
			continue
		}
		if agentUser == c.Placeholder {
			return c
		}
	}
	return fallback
}

// pgWriteError sends an ErrorResponse during the pre-auth phase
// (before AuthenticationOk). No ReadyForQuery follows — postgres
// closes the connection on auth failure.
func pgWriteError(conn net.Conn, reason string) {
	body := []byte("SFATAL\x00C28000\x00M" + reason + "\x00\x00")
	msg := append([]byte{'E'}, encUint32(uint32(len(body)+4))...)
	msg = append(msg, body...)
	_, _ = conn.Write(msg)
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
