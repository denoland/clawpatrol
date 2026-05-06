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
//  5. Forward the server Hello back to the agent (capturing the
//     negotiated revision), then run a packet-aware shuttle: the
//     first agent Query packet is parsed, fed into the SQL matcher,
//     and either forwarded (allow), gated through ConnHandle.Approve
//     (approve), or denied via a synthesized Exception packet (deny).
//     Subsequent bytes flow verbatim — multi-query inspection on a
//     single TCP session is iter 2.5.
//
// Errors before the upstream dial close the agent's conn silently —
// the native protocol has no Error packet at the pre-handshake stage
// that we could send back without first observing the server-side
// reply — but every pre-pipe failure path emits a structured
// ConnEvent{Action:"error", Reason:...} so the dashboard / JSONL
// log gets first-class signal, not just a stdout log line.
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
	//
	// Falls back to the dst host (UpstreamHost when dialed by name,
	// else the upstream host slice's first entry) when the client
	// didn't carry SNI — covers bare-IP dialing and odd clients that
	// omit it.
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
		// Splice the wrapped conn back onto the handle so downstream
		// helpers (chReadHello, chPipe) operate on plaintext.
		ch.Conn = tc
	}

	// Step 1: read agent's Hello. ClickHouse's native protocol begins
	// with a single client Hello packet (type 0). We accumulate bytes
	// until ParseChHello succeeds — typical Hellos fit in one read but
	// large client_name strings can span multiple TCP segments.
	hello, leftover, err := chReadHello(ch.Conn)
	if err != nil {
		chEmitError(ch, "read-hello", err.Error())
		return fmt.Errorf("read hello: %w", err)
	}

	// Step 2: resolve credential and inject. Single-credential native
	// endpoints today; multi-credential dispatch via placeholder lands
	// when SQL parsing does in iter 2.
	//
	// Hard-fail on secret-fetch errors and on missing real credential
	// material. Soft-failing here would leak the agent's placeholder
	// Hello upstream, which (a) reveals the placeholder shape to the
	// server and (b) produces an opaque auth-fail downstream — better
	// to drop the conn with a structured Reason and let the operator
	// fix the credential binding. Mirrors postgres's pgWriteError
	// discipline.
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

	rewritten := SerializeChHello(hello)
	if _, err := upstream.Write(rewritten); err != nil {
		chEmitError(ch, "send-hello", err.Error())
		return fmt.Errorf("send hello: %w", err)
	}
	// Any bytes the agent sent past the Hello (rare — clients usually
	// wait for ServerHello before pipelining) follow immediately.
	if len(leftover) > 0 {
		if _, err := upstream.Write(leftover); err != nil {
			chEmitError(ch, "forward-post-hello", err.Error())
			return fmt.Errorf("forward post-hello: %w", err)
		}
	}

	// Step 4: emit the connection event. One event per TCP session —
	// the native protocol is persistent, per-query parsing isn't here
	// yet, so the connection itself is the unit of audit.
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

	// Step 5: post-auth bidirectional shuttle with per-Query
	// inspection. The agent→server direction parses the first Query
	// packet, runs the SQL through the matcher, and either forwards
	// (allow), invokes the approve chain (approve), or synthesizes an
	// Exception packet and closes (deny). After the first Query is
	// handled the shuttle relays bytes verbatim — block-aware parsing
	// of subsequent client packets is iter 2.5 work; one-query-per-
	// connection covers the agent-shaped use cases that drove the
	// iter 2 ask (each agent-issued statement opens its own session).
	chRunSession(ctx, ch, upstream, hello.ProtocolRevision, credName)
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

// chRunSession is the post-auth orchestrator. It reads the server's
// Hello (forwarded verbatim to the agent so the protocol negotiation
// completes normally), captures the negotiated revision, then runs
// agent→server through the Query inspector while server→agent stays
// a pure copy.
//
// Failures past auth log + emit but do not surface — the connection
// is best-effort drained and closed.
func chRunSession(ctx context.Context, ch *runtime.ConnHandle, upstream net.Conn, clientRev uint64, credName string) {
	negotiatedRev, err := chReadAndForwardServerHello(upstream, ch.Conn)
	if err != nil {
		chEmitError(ch, "server-hello", err.Error())
		return
	}
	// Negotiated rev is min(client_rev, server_rev) — the format the
	// client uses for subsequent packets.
	if clientRev > 0 && clientRev < negotiatedRev {
		negotiatedRev = clientRev
	}

	// Server → agent: pure copy. Started before we touch agent→server
	// so any out-of-band server message (Progress, Log, etc.) makes it
	// through while the inspector buffers a Query packet.
	srvDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(ch.Conn, upstream)
		if cw, ok := ch.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(srvDone)
	}()

	chAgentToServer(ctx, ch, upstream, negotiatedRev, credName)

	// Either side closing tears the other down via CloseWrite + EOF.
	if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	<-srvDone
}

// chReadAndForwardServerHello pulls bytes from upstream until the
// server Hello has been fully buffered (just enough to extract the
// revision), forwards them to the agent verbatim, and returns the
// revision. Anything beyond the Hello that arrived in the same read
// is forwarded too — modern servers sometimes include the addendum
// random hash inline.
func chReadAndForwardServerHello(upstream net.Conn, agent net.Conn) (uint64, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := upstream.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			rev, parseErr := ParseChServerHelloRevision(buf)
			if parseErr == nil {
				if _, werr := agent.Write(buf); werr != nil {
					return 0, fmt.Errorf("forward server hello: %w", werr)
				}
				return rev, nil
			}
			if parseErr != errChShortBuffer {
				return 0, parseErr
			}
		}
		if err != nil {
			return 0, fmt.Errorf("read server hello: %w", err)
		}
		if len(buf) > 1<<20 {
			return 0, fmt.Errorf("server hello exceeded 1 MiB without parsing")
		}
	}
}

// chAgentToServer pumps the agent's outbound bytes to the upstream,
// inspecting the first Query packet for policy. Subsequent bytes
// (post-Query Data blocks, future Query packets) flow verbatim — see
// the iter 2.5 follow-up note in chRunSession's comment.
//
// On policy deny the function writes an Exception packet to the
// agent and returns; the caller closes the connection.
func chAgentToServer(ctx context.Context, ch *runtime.ConnHandle, upstream net.Conn, revision uint64, credName string) {
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	inspected := false
	for {
		n, err := ch.Conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if !inspected {
				done, consumed, deny := chMaybeInspectQuery(ctx, ch, buf, revision, credName)
				if deny {
					return
				}
				if done {
					inspected = true
					if consumed > 0 {
						if _, werr := upstream.Write(buf[:consumed]); werr != nil {
							return
						}
						buf = buf[consumed:]
					}
					if len(buf) > 0 {
						if _, werr := upstream.Write(buf); werr != nil {
							return
						}
						buf = buf[:0]
					}
				}
				// else: keep reading until we have a full packet.
			} else {
				if _, werr := upstream.Write(buf); werr != nil {
					return
				}
				buf = buf[:0]
			}
		}
		if err != nil {
			return
		}
		if !inspected && len(buf) > 4<<20 {
			// First packet didn't parse within 4 MiB — probably an
			// unsupported revision or malformed input. Stop trying to
			// inspect and forward verbatim from here on.
			chEmitError(ch, "query-parse-overflow", strconv.Itoa(len(buf)))
			if _, werr := upstream.Write(buf); werr != nil {
				return
			}
			buf = buf[:0]
			inspected = true
		}
	}
}

// chMaybeInspectQuery attempts to parse a complete client packet from
// buf. Returns:
//
//	done = true when a packet was fully decoded
//	consumed = bytes the runtime should forward (or drop, on deny)
//	deny = true when the runtime should close the connection
//
// On a Query packet the function runs the matcher + Approve chain,
// emits the per-query event, and either lets the caller forward
// (allow / approved) or writes the Exception + signals deny.
//
// On a non-Query packet the function returns done=true with consumed
// covering only the first byte — non-Query packets are forwarded
// verbatim and inspection stops; the rest of the connection becomes
// a transparent pipe.
func chMaybeInspectQuery(ctx context.Context, ch *runtime.ConnHandle, buf []byte, revision uint64, credName string) (done bool, consumed int, deny bool) {
	pktType, _, err := readChVarUInt(buf, 0)
	if err == errChShortBuffer {
		return false, 0, false
	}
	if err != nil {
		chEmitError(ch, "client-packet-type", err.Error())
		return true, 0, false
	}
	if pktType != chClientPacketQuery {
		// Cancel/Ping/etc. — let the verbatim pump take over.
		return true, 0, false
	}
	if revision < chMinRevWithSettingsAsStrings {
		// Pre-21.x clients: skip inspection and forward.
		chEmitError(ch, "unsupported-revision", strconv.FormatUint(revision, 10))
		return true, 0, false
	}
	view, perr := ParseChQuery(buf, revision)
	if perr == errChShortBuffer {
		return false, 0, false
	}
	if perr != nil {
		chEmitError(ch, "query-parse", perr.Error())
		// Fall back to verbatim forwarding rather than denying — a
		// parser miss on an exotic field set shouldn't break the
		// agent.
		return true, 0, false
	}
	verdict, reason := chEvaluateSQL(ctx, ch, view.SQL, credName)
	if verdict == "deny" {
		_, _ = ch.Conn.Write(SerializeChException(497, reason))
		log.Printf("clickhouse_native %s deny %s: %s",
			ch.Endpoint.Name, ch.PeerIP, reason)
		return true, 0, true
	}
	return true, view.End, false
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
//
// hosts entries are normalized by EndpointHosts to host:port so the
// helper can split cleanly; defaultPort is the plugin's fallback
// (9000 plaintext / 9440 TLS) used only when an entry slipped through
// without a port.
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

// chReadHello reads from r until enough bytes have arrived to fully
// decode a client Hello. Returns the parsed packet and any leftover
// bytes already pulled past the Hello (rare — clients usually wait
// for ServerHello before sending more — but possible).
//
// ClickHouse's native protocol prefixes nothing about packet length:
// the Hello is a sequence of VarUInt + length-prefixed strings.
// ParseChHello is incremental — we attempt a parse on each read and
// retry when errChShortBuffer surfaces.
func chReadHello(r io.Reader) (ChHello, []byte, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, readErr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			h, consumed, err := ParseChHello(buf)
			if err == nil {
				return h, buf[consumed:], nil
			}
			if err != errChShortBuffer {
				return ChHello{}, nil, err
			}
		}
		if readErr != nil {
			if readErr == io.EOF && len(buf) > 0 {
				return ChHello{}, nil, fmt.Errorf("hello truncated after %d bytes", len(buf))
			}
			return ChHello{}, nil, readErr
		}
		if len(buf) > 1<<20 {
			return ChHello{}, nil, fmt.Errorf("hello exceeded 1 MiB without parsing")
		}
	}
}
