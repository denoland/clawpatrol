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
//  5. Bidirectional pipe until either side closes.
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
	if cc := chPickCredential(ch.Endpoint); cc != nil {
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
		tc := tls.Client(upstream, &tls.Config{ServerName: host})
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

	// Step 5: bidirectional pipe.
	chPipe(ch.Conn, upstream)
	return nil
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

// chPipe shuttles bytes between agent and upstream, half-closing each
// direction on EOF. Mirrors main.pipe but lives here so the plugin
// stays self-contained.
func chPipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
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
