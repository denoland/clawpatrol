package endpoints

// postgres endpoint: schema, plugin registration, wire-protocol
// gateway, and SCRAM/cleartext auth offload. All postgres-specific
// code lives in this single file.
//
// Endpoint shape — operator-edited HCL:
//
//   endpoint "postgres" "writer" {
//     host       = "db.example.com:5432"
//     database   = "postgres"
//     sslmode    = "prefer"        // disable | prefer | require | verify-full
//     credential = pg-writer-cred
//   }
//
// Wire-protocol gateway: ConnEndpointRuntime intercepts client→server
// messages (Query / Parse), runs them through the SQL family matcher
// against the endpoint's compiled rules, and either forwards or
// sends an ErrorResponse + ReadyForQuery so the agent can continue.
//
// Auth offload: gateway terminates SCRAM (or cleartext / trust) on
// the upstream side using the credential's (user, password) and
// synthesizes AuthenticationOk for the agent — agent never
// participates in the SCRAM handshake. SCRAM-SHA-256 is designed to
// defeat MITM swap, so the gateway has to BE one of the peers.
//
// Wire format (post-startup):
//
//	[type:1][length:4 BE incl. self][payload: length-4]
//
// StartupMessage / SSLRequest skip the type byte.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/crypto/pbkdf2"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"
)

// PostgresEndpoint addresses a single RDS-or-equivalent server.
// Tunnel topologies (kubectl-portforward-ssh and friends) aren't
// supported in this iteration — operators run the gateway with
// network reachability already arranged.
//
// SSLMode mirrors libpq's sslmode names — "disable" / "prefer" /
// "require" / "verify-full". Default "prefer": try TLS, fall back
// to plain when the upstream replies 'N'. "require" hard-fails on
// 'N'. "verify-full" additionally validates the upstream cert
// against Host. "disable" skips the SSLRequest probe entirely —
// fine for self-hosted pg on a private network where WG already
// encrypts the path.
type PostgresEndpoint struct {
	Host           string    `hcl:"host"`
	Database       string    `hcl:"database"`
	SSLMode        string    `hcl:"sslmode,optional"`
	Credential     string    `hcl:"credential,optional"`
	CredentialsRaw cty.Value `hcl:"credentials,optional" json:"-"`

	Credentials []CredentialEntry `json:"Credentials,omitempty"`
}

func (e *PostgresEndpoint) EndpointHosts() []string { return []string{e.Host} }
func (e *PostgresEndpoint) EndpointCredentials() []config.CredBinding {
	return bindings(e.Credential, e.Credentials)
}

// ConnRouteHosts implements runtime.ConnRouter — postgres traffic
// arrives at the WG forwarder as raw conns (no SNI), so the gateway
// indexes the upstream host:port → endpoint at policy-load time.
// The compile pass skips this entry for tunneled endpoints: those
// route through the VIP path, not real-IP dispatch.
func (e *PostgresEndpoint) ConnRouteHosts() []string { return []string{e.Host} }

func (e *PostgresEndpoint) credentialAndRaw() (string, cty.Value) {
	return e.Credential, e.CredentialsRaw
}
func (e *PostgresEndpoint) setCredentialEntries(es []CredentialEntry) { e.Credentials = es }

// PostgresEndpointRuntime detects placeholders in a postgres
// StartupMessage. The wire-protocol front-end populates Request with
// a SQL meta whose Statement field carries the agent's submitted
// password verbatim before injection.
type PostgresEndpointRuntime struct{}

func (PostgresEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.SQL == nil {
		return ""
	}
	hay := req.SQL.Statement
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

func init() {
	var _ runtime.PlaceholderDetector = PostgresEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "postgres",
		Family:   "sql",
		New:      func() any { return &PostgresEndpoint{} },
		Refs:     singularRef,
		Validate: multiCredValidate,
		Runtime:  PostgresEndpointRuntime{},
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*PostgresEndpoint)
			b.SetAttributeValue("host", cty.StringVal(e.Host))
			b.SetAttributeValue("database", cty.StringVal(e.Database))
			emitCredentialBinding(b, e.Credential, e.Credentials, "placeholder")
		},
	})
}

// ── Wire-protocol gateway ─────────────────────────────────────────────

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
// returns the disposition for this query. Emits a per-query event in
// every branch (allow, deny, hitl_allow, hitl_deny) so the dashboard
// surfaces the activity even when no rule fires — endpoints with
// zero rules still log every query as "allow".
//
// Returns:
//
//	("deny", reason) — matched rule denies, or approve chain
//	  rejected, or approve chain timed out (host applies its
//	  configured fail mode).
//	("", "")         — no rule fires or the matched rule allows.
func pgEvaluate(ch *runtime.ConnHandle, sql, credName string) (string, string) {
	info := parseSQL(sql)
	summary := pgSummary(info)
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
		// No rule matched — implicit allow. Emit so the query
		// shows up in the dashboard's actions tab anyway; the
		// HTTP path does the same (main.go:1909 — every request
		// gets an `allow` event when no explicit verdict was
		// recorded).
		emit(ch, runtime.ConnEvent{
			Action: "allow", Verb: info.Verb, Summary: summary,
		})
		return "", ""
	}

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

// ── Upstream auth: SCRAM / cleartext / trust ──────────────────────────

const sslRequestCodeUpstream uint32 = 80877103

// pgUpgradeSSL probes the upstream for TLS support via the standard
// SSLRequest pre-startup probe, then wraps the connection in TLS
// when the server agrees ('S'). Returns the upgraded conn, or nil
// when the server refused and sslmode permits plaintext.
//
// sslmode semantics (libpq-compatible):
//
//   - prefer      → try TLS, fall back to plain on 'N'
//   - require     → try TLS, error on 'N'
//   - verify-full → require + validate cert against pgEp.Host
func pgUpgradeSSL(upstream net.Conn, pgEp *PostgresEndpoint, sslmode string) (net.Conn, error) {
	// Send SSLRequest: [int32 length=8][int32 code=80877103].
	probe := make([]byte, 8)
	binary.BigEndian.PutUint32(probe[:4], 8)
	binary.BigEndian.PutUint32(probe[4:8], sslRequestCodeUpstream)
	if _, err := upstream.Write(probe); err != nil {
		return nil, fmt.Errorf("write SSLRequest: %w", err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(upstream, reply); err != nil {
		return nil, fmt.Errorf("read SSLRequest reply: %w", err)
	}
	switch reply[0] {
	case 'S':
		host := ""
		if pgEp != nil {
			host = pgEp.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		cfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: sslmode != "verify-full",
		}
		secured := tls.Client(upstream, cfg)
		if err := secured.Handshake(); err != nil {
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return secured, nil
	case 'N':
		if sslmode == "require" || sslmode == "verify-full" {
			return nil, fmt.Errorf("upstream refused TLS but sslmode=%q requires it", sslmode)
		}
		return nil, nil // continue plaintext
	default:
		return nil, fmt.Errorf("unexpected SSLRequest reply byte %q", reply[0])
	}
}

const (
	pgAuthOK            uint32 = 0
	pgAuthCleartextPass uint32 = 3
	pgAuthMD5Pass       uint32 = 5
	pgAuthSASL          uint32 = 10
	pgAuthSASLContinue  uint32 = 11
	pgAuthSASLFinal     uint32 = 12
)

// pgSendStartup writes a v3 StartupMessage(user, database) to upstream.
// Other params (application_name, client_encoding) are intentionally
// omitted — the agent renegotiates them via Set after auth completes.
func pgSendStartup(w io.Writer, user, database string) error {
	var params []byte
	addParam := func(k, v string) {
		params = append(params, []byte(k)...)
		params = append(params, 0)
		params = append(params, []byte(v)...)
		params = append(params, 0)
	}
	addParam("user", user)
	if database != "" && database != user {
		addParam("database", database)
	}
	params = append(params, 0) // terminator

	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 196608) // protocol version 3.0
	body = append(body, params...)

	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(body)+4))
	out = append(out, body...)
	_, err := w.Write(out)
	return err
}

// pgReadAuthFrame reads one type-prefixed frame from upstream.
// Returns the type byte, length-prefixed payload, and any error.
func pgReadAuthFrame(r io.Reader) (typ byte, payload []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	typ = hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || length > 1<<20 {
		return 0, nil, fmt.Errorf("pg: bogus auth frame length %d", length)
	}
	payload = make([]byte, length-4)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// pgWriteFrame serializes one tagged frame to w.
func pgWriteFrame(w io.Writer, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// pgPerformAuth drives the upstream auth handshake using (user, password).
// Returns the buffered post-auth bytes (AuthenticationOk through and
// including ReadyForQuery) the relay loop must replay to the agent.
//
// Walks Authentication* frames; halts on the first non-Authentication
// frame and returns it concatenated to anything else read.
func pgPerformAuth(upstream net.Conn, user, password string) ([]byte, error) {
	var postAuth []byte
	scram := newScramClient(user, password)
	for {
		typ, payload, err := pgReadAuthFrame(upstream)
		if err != nil {
			return nil, fmt.Errorf("read auth frame: %w", err)
		}
		if typ != 'R' {
			// ParameterStatus / BackendKeyData / NoticeResponse / etc.
			// arrive after AuthenticationOk; collect them so the relay
			// can replay.
			postAuth = append(postAuth, frameBytes(typ, payload)...)
			if typ == 'Z' /* ReadyForQuery */ {
				return postAuth, nil
			}
			if typ == 'E' /* ErrorResponse */ {
				return postAuth, fmt.Errorf("upstream error: %s", parseErrorFields(payload))
			}
			continue
		}
		if len(payload) < 4 {
			return nil, fmt.Errorf("pg: short auth payload")
		}
		code := binary.BigEndian.Uint32(payload[:4])
		switch code {
		case pgAuthOK:
			postAuth = append(postAuth, frameBytes(typ, payload)...)
			// Continue reading until ReadyForQuery — server still
			// sends ParameterStatus / BackendKeyData first.
		case pgAuthCleartextPass:
			out := append([]byte(password), 0)
			if err := pgWriteFrame(upstream, 'p', out); err != nil {
				return nil, err
			}
		case pgAuthMD5Pass:
			return nil, fmt.Errorf("pg: upstream uses MD5 auth, only SCRAM-SHA-256 + cleartext + trust supported")
		case pgAuthSASL:
			// Mechanism list is null-terminated strings followed by
			// a zero terminator.
			mechs := splitCStrings(payload[4:])
			ok := false
			for _, m := range mechs {
				if m == "SCRAM-SHA-256" {
					ok = true
					break
				}
			}
			if !ok {
				return nil, fmt.Errorf("pg: upstream offered SASL mechanisms %v, want SCRAM-SHA-256", mechs)
			}
			out := scram.initialResponse()
			if err := pgWriteFrame(upstream, 'p', out); err != nil {
				return nil, err
			}
		case pgAuthSASLContinue:
			out, err := scram.continueResponse(payload[4:])
			if err != nil {
				return nil, fmt.Errorf("scram continue: %w", err)
			}
			if err := pgWriteFrame(upstream, 'p', out); err != nil {
				return nil, err
			}
		case pgAuthSASLFinal:
			if err := scram.finalize(payload[4:]); err != nil {
				return nil, fmt.Errorf("scram final: %w", err)
			}
		default:
			return nil, fmt.Errorf("pg: unsupported auth code %d", code)
		}
	}
}

func frameBytes(typ byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)+4))
	copy(out[5:], payload)
	return out
}

func splitCStrings(b []byte) []string {
	var out []string
	for {
		i := 0
		for i < len(b) && b[i] != 0 {
			i++
		}
		if i == 0 {
			break
		}
		out = append(out, string(b[:i]))
		if i+1 > len(b) {
			break
		}
		b = b[i+1:]
	}
	return out
}

func parseErrorFields(b []byte) string {
	// Each field: type byte + null-terminated string. Stop on type 0.
	var sb strings.Builder
	for len(b) > 0 {
		if b[0] == 0 {
			break
		}
		t := b[0]
		b = b[1:]
		end := 0
		for end < len(b) && b[end] != 0 {
			end++
		}
		val := string(b[:end])
		if end < len(b) {
			b = b[end+1:]
		} else {
			b = nil
		}
		if t == 'M' || t == 'C' {
			if sb.Len() > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(val)
		}
	}
	return sb.String()
}

// pgWriteAuthOK sends a synthetic AuthenticationOk to the agent so it
// proceeds as if it just completed auth itself. Followed by the
// upstream's ParameterStatus / BackendKeyData / ReadyForQuery bytes
// (already collected during pgPerformAuth).
func pgWriteAuthOK(w io.Writer, postAuth []byte) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, pgAuthOK)
	if err := pgWriteFrame(w, 'R', payload); err != nil {
		return err
	}
	// Skip the leading AuthenticationOk in postAuth — we just sent
	// our own. The first frame in postAuth IS the upstream's
	// AuthenticationOk; strip it.
	rest := postAuth
	if len(rest) >= 5 && rest[0] == 'R' {
		l := binary.BigEndian.Uint32(rest[1:5])
		if int(1+l) <= len(rest) {
			rest = rest[1+l:]
		}
	}
	if len(rest) > 0 {
		_, err := w.Write(rest)
		return err
	}
	return nil
}

// ── SCRAM-SHA-256 client — RFC 5802 + 7677 ────────────────────────────
//
// Trimmed implementation: gs2-header is "n,," (no channel binding,
// no authzid). Nonce is 24 random bytes base64'd. We don't validate
// the channel-binding round trip beyond the standard.

type scramClient struct {
	user            string
	password        string
	clientNonce     string
	clientFirstBare string
	serverFirst     string
}

func newScramClient(user, password string) *scramClient {
	nb := make([]byte, 24)
	_, _ = rand.Read(nb)
	return &scramClient{
		user:        user,
		password:    password,
		clientNonce: base64.StdEncoding.EncodeToString(nb),
	}
}

func (s *scramClient) initialResponse() []byte {
	s.clientFirstBare = "n=" + s.user + ",r=" + s.clientNonce
	clientFirst := "n,," + s.clientFirstBare
	// SASLInitialResponse payload: mechanism\0 + int32(len) + initial-resp
	mech := []byte("SCRAM-SHA-256\x00")
	resp := []byte(clientFirst)
	out := make([]byte, 0, len(mech)+4+len(resp))
	out = append(out, mech...)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(resp)))
	out = append(out, lenBuf...)
	out = append(out, resp...)
	return out
}

func (s *scramClient) continueResponse(serverFirst []byte) ([]byte, error) {
	s.serverFirst = string(serverFirst)
	parts := parseSCRAMAttrs(s.serverFirst)
	r := parts["r"]
	saltB64 := parts["s"]
	iterStr := parts["i"]
	if r == "" || saltB64 == "" || iterStr == "" {
		return nil, fmt.Errorf("malformed server-first: %q", s.serverFirst)
	}
	if !strings.HasPrefix(r, s.clientNonce) {
		return nil, fmt.Errorf("server nonce doesn't extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("salt decode: %w", err)
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 {
		return nil, fmt.Errorf("bad iteration count: %q", iterStr)
	}
	// gs2-header base64'd as "biws" = "n,,"
	clientFinalNoProof := "c=biws,r=" + r
	saltedPassword := pbkdf2.Key([]byte(s.password), salt, iter, 32, sha256.New)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256Sum(clientKey)
	authMessage := s.clientFirstBare + "," + s.serverFirst + "," + clientFinalNoProof
	clientSignature := hmacSHA256(storedKey, []byte(authMessage))
	clientProof := xorBytes(clientKey, clientSignature)
	clientFinal := clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)
	return []byte(clientFinal), nil
}

func (s *scramClient) finalize(serverFinal []byte) error {
	parts := parseSCRAMAttrs(string(serverFinal))
	if e := parts["e"]; e != "" {
		return fmt.Errorf("server reported scram error: %s", e)
	}
	v := parts["v"]
	if v == "" {
		return fmt.Errorf("server-final missing verifier")
	}
	// Optional: verify ServerSignature. Skip — upstream gave us
	// AuthenticationOk after this, which we trust.
	_ = v
	return nil
}

func parseSCRAMAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		out[kv[:eq]] = kv[eq+1:]
	}
	return out
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
