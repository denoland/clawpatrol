package endpoints

// Per-connection runtime for the clickhouse_native endpoint. Schema
// and registration live in clickhouse_native.go.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	chcompress "github.com/ClickHouse/ch-go/compress"
	chgoproto "github.com/ClickHouse/ch-go/proto"
	chproto "github.com/ClickHouse/clickhouse-go/v2/lib/proto"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"
)

// HandleConn services one inbound native-protocol connection.
//
// Flow:
//
//  1. Read the agent's first packet, parse Hello.
//  2. Resolve the bound credential, fetch its secret. Swap any
//     placeholder substring inside Hello.username / Hello.password.
//  3. Dial upstream (TLS or plain), send the (possibly modified) Hello.
//  4. Emit one ConnEvent describing the session.
//  5. Read the server Hello (forwarded back to the agent), capture
//     the negotiated revision, then run an agent → server pump that
//     decodes every client packet via ch-go / lib/proto: Query packets
//     feed the SQL matcher with the agent's compression preference
//     preserved verbatim, uncompressed Data blocks decode through
//     lib/proto.Block, compressed Data blocks forward chunk bytes
//     opaquely while a decompressing reader walks far enough to find
//     the block boundary. Cancel/Ping forward as-is. Server → agent
//     stays a pure copy past the Hello.
func (ClickhouseNativeEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer ch.Conn.Close()
	if ch.Endpoint == nil || ch.Endpoint.Family != "sql" {
		err := fmt.Errorf("clickhouse_native runtime invoked on non-sql endpoint %v", ch.Endpoint)
		chEmitError(ch, "wrong-family", "")
		return err
	}
	chEp, ok := ch.Endpoint.Body.(*ClickhouseNativeEndpoint)
	if !ok {
		err := fmt.Errorf("clickhouse_native runtime invoked on non-native endpoint %v", ch.Endpoint)
		chEmitError(ch, "wrong-endpoint-type", ch.Endpoint.Name)
		return err
	}
	upstreamAddr := chPickUpstream(ch.Endpoint.Hosts, ch.UpstreamHost, ch.DstPort, chEp.port())
	if upstreamAddr == "" {
		chEmitError(ch, "no-host", ch.Endpoint.Name)
		return fmt.Errorf("clickhouse_native endpoint %q has no host", ch.Endpoint.Name)
	}

	// Inbound TLS termination. The wrapped agent (clickhouse-client
	// --secure, etc.) speaks native-over-TLS exactly as it would
	// against the real upstream; we terminate here using a leaf
	// minted off the gateway CA so the SAN matches whatever SNI the
	// agent sent. Agents already trust the gateway CA via the
	// SSL_CERT_FILE env-var pushdown that `clawpatrol run` stamps,
	// so verification passes without any client-side opt-out.
	if chEp.TLS && ch.MintCert != nil {
		fallback := ch.UpstreamHost
		if fallback == "" {
			h, _ := chHostPort(upstreamAddr)
			fallback = h
		}
		mint := ch.MintCert
		tc := tls.Server(ch.Conn, &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				host := chi.ServerName
				if host == "" {
					host = fallback
				}
				return mint(host)
			},
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			chEmitError(ch, "inbound-tls-handshake", err.Error())
			return fmt.Errorf("inbound tls: %w", err)
		}
		ch.Conn = tc
	}

	// Step 1: read agent Hello. Once the conn is wrapped in a
	// chgoproto.Reader the underlying bytes are buffered; subsequent
	// agent → server packets must transcode through that reader.
	hello, agentReader, err := chReadHello(ch.Conn)
	if err != nil {
		chEmitError(ch, "read-hello", err.Error())
		return fmt.Errorf("read hello: %w", err)
	}

	// Step 2: resolve credential and inject. Single-credential native
	// endpoints today; multi-credential dispatch via placeholder lands
	// when SQL parsing does in iter 2.
	claimedUser := hello.Username
	injected := false
	credName := ""
	if cc := chPickCredential(ch.Endpoint); cc != nil {
		credName = cc.Credential.Symbol.Name
		auth, ok := cc.Credential.Body.(runtime.ClickhouseAuthCredential)
		if !ok {
			chEmitError(ch, "credential-not-clickhouse-auth", cc.Credential.Symbol.Name)
			return fmt.Errorf("clickhouse_native: credential %q does not implement ClickhouseAuthCredential",
				cc.Credential.Symbol.Name)
		}
		sec, secErr := ch.Secrets.Get(cc.Credential.Symbol.Name, ch.Profile)
		if secErr != nil {
			chEmitError(ch, "secret-fetch", fmt.Sprintf("%s: %v", cc.Credential.Symbol.Name, secErr))
			return fmt.Errorf("clickhouse_native: fetch secret %q: %w", cc.Credential.Symbol.Name, secErr)
		}
		realUser, realPassword := auth.ClickhouseAuth(sec)
		if realUser == "" || realPassword == "" {
			chEmitError(ch, "secret-empty", cc.Credential.Symbol.Name)
			return fmt.Errorf("clickhouse_native: credential %q produced empty user or password",
				cc.Credential.Symbol.Name)
		}
		before := hello.Username + "\x00" + hello.Password
		hello.Username = realUser
		hello.Password = realPassword
		if hello.Username+"\x00"+hello.Password != before {
			injected = true
		}
	}

	// Step 3: dial upstream + send hello.
	upstream, err := ch.DialUpstream(ctx, "tcp", upstreamAddr)
	if err != nil {
		chEmitError(ch, "dial-upstream", fmt.Sprintf("%s: %v", upstreamAddr, err))
		return fmt.Errorf("dial upstream %s: %w", upstreamAddr, err)
	}
	defer upstream.Close()

	if chEp.TLS {
		host := upstreamAddr
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		tc := tls.Client(upstream, chUpstreamTLSConfig(host, chEp.AcceptInvalidCertificate))
		if err := tc.HandshakeContext(ctx); err != nil {
			chEmitError(ch, "tls-handshake", err.Error())
			return fmt.Errorf("upstream tls: %w", err)
		}
		upstream = tc
	}

	if _, err := upstream.Write(chEncodeHello(hello)); err != nil {
		chEmitError(ch, "send-hello", err.Error())
		return fmt.Errorf("send hello: %w", err)
	}

	// Step 4: emit the connection event. One event per TCP session —
	// per-Query events come from the agent → server pump below.
	database := hello.Database
	if database == "" {
		database = "default"
	}
	host, port := chHostPort(upstreamAddr)
	summary := fmt.Sprintf("%s@%s:%d/%s", hello.Username, host, port, database)
	if injected {
		summary += " (placeholder injected)"
	}
	if ch.Emit != nil {
		ch.Emit(runtime.ConnEvent{
			Action:  "allow",
			Verb:    "connect",
			Summary: summary,
		})
	}
	log.Printf("clickhouse_native %s: connect user=%q claimed=%q db=%q client=%q rev=%d injected=%v",
		ch.Endpoint.Name, hello.Username, claimedUser, database,
		hello.ClientName, hello.ProtocolRevision, injected)

	// Step 5: post-handshake bidirectional shuttle. Server → agent
	// stays a pure copy (decoded only far enough to forward the
	// ServerHello and capture the revision). Agent → server is fully
	// transcoded.
	chRunSession(ctx, ch, agentReader, upstream, hello.ProtocolRevision, credName)
	return nil
}

// chUpstreamTLSConfig builds the upstream tls.Config from the
// endpoint's AcceptInvalidCertificate flag. False (default) keeps the
// public-roots, hostname-matched check. True disables both —
// necessary for self-hosted ClickHouse fronted by a private CA, at
// the cost of trusting whatever cert the upstream presents (MITM
// exposure on the wg→clickhouse hop). Operators opt in per endpoint;
// the default stays safe.
func chUpstreamTLSConfig(host string, acceptInvalidCert bool) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: acceptInvalidCert,
	}
}

// chRunSession orchestrates the post-Hello exchange. Reads the
// server Hello (forwarded verbatim to the agent), captures the
// negotiated revision, then runs agent → server through the Query /
// Data inspector while server → agent stays a pure passthrough.
func chRunSession(ctx context.Context, ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream net.Conn, clientRev int, credName string) {
	upstreamReader := chgoproto.NewReader(upstream)
	negotiatedRev, err := chReadAndForwardServerHello(upstreamReader, ch.Conn, clientRev)
	if err != nil {
		chEmitError(ch, "server-hello", err.Error())
		return
	}

	// Server → agent: pure copy via the wrapped reader (delegates to
	// the underlying bufio.Reader once the Hello bytes have been
	// drained). Started before agent → server so any out-of-band
	// server message (Progress, Log, etc.) makes it through while the
	// inspector buffers a Query packet.
	srvDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(ch.Conn, upstreamReader)
		if cw, ok := ch.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(srvDone)
	}()

	chAgentToServer(ctx, ch, agentReader, upstream, negotiatedRev, credName)

	if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	<-srvDone
}

// chAgentToServer is the agent → server transcoding pump. Each
// iteration reads one packet code off the agent reader, dispatches
// to a per-packet handler that decodes the body, and writes the
// (possibly re-encoded) packet to upstream. On policy deny the
// function writes an Exception to the agent and returns; the caller
// closes the connection.
//
// Compression: the agent's `compression` flag on the Query packet
// is forwarded verbatim and tracked here so subsequent Data packets
// take the right code path — uncompressed blocks round-trip through
// lib/proto.Block.Decode/Encode, compressed blocks forward chunk
// bytes opaquely with a decompressing reader walking just far enough
// to find the block boundary.
func chAgentToServer(ctx context.Context, ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream io.Writer, revision int, credName string) {
	compression := chgoproto.CompressionDisabled
	for {
		code, err := agentReader.UInt8()
		if err != nil {
			return
		}
		switch chgoproto.ClientCode(code) {
		case chgoproto.ClientCodeQuery:
			next, ok := chHandleQuery(ctx, ch, agentReader, upstream, revision, credName)
			if !ok {
				return
			}
			compression = next
		case chgoproto.ClientCodeData:
			if !chHandleData(ch, agentReader, upstream, revision, compression) {
				return
			}
		case chgoproto.ClientCodeCancel, chgoproto.ClientCodePing:
			// Headerless packets — single byte, forward verbatim.
			if _, werr := upstream.Write([]byte{code}); werr != nil {
				return
			}
		default:
			// Unknown / future packet type — log and stop. We can't
			// safely forward an unknown packet because we don't know
			// its body length to skip past it.
			chEmitError(ch, "unknown-client-packet", strconv.Itoa(int(code)))
			return
		}
	}
}

// chHandleQuery decodes one client Query packet, runs the SQL through
// the matcher, and forwards the re-encoded packet to upstream with
// the agent's `compression` choice preserved. The returned flag is
// what subsequent Data packets on this session will be framed with.
//
// Returns (_, false) on policy deny (caller tears down the connection)
// or transport error.
func chHandleQuery(ctx context.Context, ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream io.Writer, revision int, credName string) (chgoproto.Compression, bool) {
	var q chgoproto.Query
	if err := q.DecodeAware(agentReader, revision); err != nil {
		chEmitError(ch, "query-decode", err.Error())
		return chgoproto.CompressionDisabled, false
	}
	verdict, reason := chEvaluateSQL(ctx, ch, q.Body, credName)
	if verdict == "deny" {
		_, _ = ch.Conn.Write(chEncodeException(reason))
		log.Printf("clickhouse_native %s deny %s: %s",
			ch.Endpoint.Name, ch.PeerIP, reason)
		return chgoproto.CompressionDisabled, false
	}

	var b chgoproto.Buffer
	q.EncodeAware(&b, revision)
	if _, werr := upstream.Write(b.Buf); werr != nil {
		return chgoproto.CompressionDisabled, false
	}
	return q.Compression, true
}

// chHandleData decodes one client Data packet (table-name header +
// Block) and forwards it to upstream. Two paths depending on the
// session's negotiated compression:
//
//   - Disabled: full Block.Decode → Block.Encode round-trip. The
//     gateway sees columns it can later route to a block-aware
//     matcher and re-emits a wire-equivalent block.
//
//   - Enabled: chunk bytes flow to upstream verbatim through an
//     io.TeeReader. A ch-go/compress.Reader on top decompresses
//     just enough to feed Block.Decode, which finds the block
//     boundary without the gateway re-encoding (or re-compressing)
//     the column payload. The materialized block is used only to
//     populate the data event — the bytes on the inner hop are the
//     agent's own compressed bytes.
func chHandleData(ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream io.Writer, revision int, compression chgoproto.Compression) bool {
	var hdr chgoproto.ClientData
	if err := hdr.DecodeAware(agentReader, revision); err != nil {
		chEmitError(ch, "data-header-decode", err.Error())
		return false
	}
	var headBuf chgoproto.Buffer
	headBuf.PutByte(byte(chgoproto.ClientCodeData))
	hdr.EncodeAware(&headBuf, revision)
	if _, werr := upstream.Write(headBuf.Buf); werr != nil {
		return false
	}

	if compression == chgoproto.CompressionEnabled {
		teed := io.TeeReader(agentReader, upstream)
		decomp := chcompress.NewReader(teed)
		pr := chgoproto.NewReader(decomp)
		block := chproto.NewBlock()
		if err := block.Decode(pr, uint64(revision)); err != nil {
			chEmitError(ch, "data-block-decode", err.Error())
			return false
		}
		if ch.Emit != nil {
			summary := fmt.Sprintf("data table=%q rows=%d cols=%d (compressed)",
				hdr.TableName, block.Rows(), len(block.Columns))
			ch.Emit(runtime.ConnEvent{Action: "allow", Verb: "data", Summary: summary})
		}
		return true
	}

	block := chproto.NewBlock()
	if err := block.Decode(agentReader, uint64(revision)); err != nil {
		chEmitError(ch, "data-block-decode", err.Error())
		return false
	}
	if ch.Emit != nil {
		summary := fmt.Sprintf("data table=%q rows=%d cols=%d", hdr.TableName, block.Rows(), len(block.Columns))
		ch.Emit(runtime.ConnEvent{Action: "allow", Verb: "data", Summary: summary})
	}
	var b chgoproto.Buffer
	if err := block.Encode(&b, uint64(revision)); err != nil {
		chEmitError(ch, "data-block-encode", err.Error())
		return false
	}
	if _, werr := upstream.Write(b.Buf); werr != nil {
		return false
	}
	return true
}

// chEvaluateSQL runs SQL through the endpoint's compiled rules. The
// shape mirrors pgEvaluate so the SQL family rule semantics stay
// consistent across plugins — same Match.Request fields, same allow /
// deny / approve verdicts.
//
// Returns:
//
//	("deny", reason) — matched rule denies, or approve rejected.
//	("", "")         — no rule fires, or the matched rule allows.
func chEvaluateSQL(ctx context.Context, ch *runtime.ConnHandle, sql, credName string) (string, string) {
	info := parseChSQL(sql)
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
		chEmit(ch, runtime.ConnEvent{
			Action: "allow", Verb: info.Verb, Summary: chSummary(info),
		})
		return "", ""
	}
	summary := chSummary(info)

	if len(cr.Outcome.Approve) > 0 {
		if ch.Approve == nil {
			chEmit(ch, runtime.ConnEvent{
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
			chEmit(ch, runtime.ConnEvent{
				Action: "hitl_deny", Reason: reason,
				Verb: info.Verb, Summary: summary,
			})
			return "deny", reason
		}
		chEmit(ch, runtime.ConnEvent{
			Action: "hitl_allow", Verb: info.Verb, Summary: summary,
		})
		return "", ""
	}

	if cr.Outcome.Verdict == "deny" {
		reason := cr.Outcome.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		chEmit(ch, runtime.ConnEvent{
			Action: "deny", Reason: reason,
			Verb: info.Verb, Summary: summary,
		})
		return "deny", reason
	}
	chEmit(ch, runtime.ConnEvent{
		Action: "allow", Verb: info.Verb, Summary: summary,
	})
	_ = ctx
	return "", ""
}

func chEmit(ch *runtime.ConnHandle, ev runtime.ConnEvent) {
	if ch != nil && ch.Emit != nil {
		ch.Emit(ev)
	}
}

// chEmitError emits a structured error ConnEvent if the host wired
// an emit callback. Reason is a stable short tag, Detail is free
// form (error message, name, etc.) — keep the dashboard's filter
// surface narrow.
func chEmitError(ch *runtime.ConnHandle, reason, detail string) {
	if ch == nil || ch.Emit == nil {
		return
	}
	summary := reason
	if detail != "" {
		summary = reason + ": " + detail
	}
	ch.Emit(runtime.ConnEvent{
		Action:  "error",
		Verb:    "connect",
		Reason:  reason,
		Summary: summary,
	})
}

// chPickCredential returns the (only) credential bound to the
// endpoint, or nil. Multi-credential dispatch by placeholder will
// move into the SQL-parsing iteration.
func chPickCredential(ep *config.CompiledEndpoint) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	return ep.Credentials[0]
}

// chPickUpstream resolves the upstream addr the plugin should dial.
//
// Preference order:
//
//  1. (upstreamHost, dstPort) — VIP-dispatched conns: the agent
//     dialed a specific hostname which dnsvip mapped to a VIP plus
//     the matched port; that pair is the canonical upstream.
//  2. host whose declared port equals dstPort — disambiguates
//     multi-host endpoints where each member runs on a different
//     port (rare but legal).
//  3. first non-empty host — single-host endpoint, or the operator
//     just declared one.
func chPickUpstream(hosts []string, upstreamHost string, dstPort uint16, defaultPort int) string {
	if upstreamHost != "" && dstPort != 0 {
		return net.JoinHostPort(upstreamHost, strconv.Itoa(int(dstPort)))
	}
	if dstPort != 0 {
		want := strconv.Itoa(int(dstPort))
		for _, h := range hosts {
			if h == "" {
				continue
			}
			if _, p, err := net.SplitHostPort(h); err == nil && p == want {
				return h
			}
		}
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err == nil {
			return h
		}
		return net.JoinHostPort(h, strconv.Itoa(defaultPort))
	}
	return ""
}

func chHostPort(addr string) (string, int) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return h, 0
	}
	return h, port
}
