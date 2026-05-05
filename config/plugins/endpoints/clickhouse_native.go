package endpoints

// clickhouse_native endpoint: ClickHouse's binary native protocol
// (default port 9000 plaintext / 9440 TLS). Pairs with
// clickhouse_https for the same upstream cluster.
//
// Iter 1 scope: parse the Hello packet, swap placeholder bytes in
// the agent-supplied (username, password) for the credential's real
// values, emit one connection event, then transparent bidirectional
// pipe. SQL parsing lands in a follow-up iteration.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// ClickhouseNativeEndpoint addresses one ClickHouse server reachable
// via the binary native protocol. Operators bind a single
// clickhouse_credential; the runtime parses the agent's Hello and
// substitutes the credential's (user, password) where the agent
// embedded a placeholder.
//
// TLS toggles upstream TLS-wrapping. The native protocol is
// persistent (no inner TLS negotiation), so this is a one-time
// decision per endpoint. Default false: WG already encrypts
// agent→gateway and most self-hosted ClickHouse on a private network
// runs plaintext on 9000. Operators using cloud ClickHouse on 9440
// flip TLS=true and set Port=9440.
type ClickhouseNativeEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Port       int      `hcl:"port,optional"`
	TLS        bool     `hcl:"tls,optional"`
	Credential string   `hcl:"credential,optional"`
}

func (e *ClickhouseNativeEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *ClickhouseNativeEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

// ConnRouteHosts implements runtime.ConnRouter — clickhouse native
// arrives at the WG forwarder as raw conns (no SNI), so the gateway
// indexes the upstream host:port → endpoint at policy-load time.
func (e *ClickhouseNativeEndpoint) ConnRouteHosts() []string {
	port := e.port()
	out := make([]string, 0, len(e.Hosts))
	for _, h := range e.Hosts {
		out = append(out, fmt.Sprintf("%s:%d", h, port))
	}
	return out
}

func (e *ClickhouseNativeEndpoint) port() int {
	if e.Port > 0 {
		return e.Port
	}
	return 9000
}

// ClickhouseNativeEndpointRuntime is the per-connection handler.
// Stateless — all per-session state lives on ConnHandle.
type ClickhouseNativeEndpointRuntime struct{}

func init() {
	var _ runtime.ConnEndpointRuntime = ClickhouseNativeEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:    config.KindEndpoint,
		Type:    "clickhouse_native",
		Family:  "sql",
		New:     func() any { return &ClickhouseNativeEndpoint{} },
		Refs:    singularRef,
		Runtime: ClickhouseNativeEndpointRuntime{},
		Build:   passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*ClickhouseNativeEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			if e.Port > 0 {
				b.SetAttributeValue("port", cty.NumberIntVal(int64(e.Port)))
			}
			if e.TLS {
				b.SetAttributeValue("tls", cty.BoolVal(true))
			}
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}

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
// reply.
func (ClickhouseNativeEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer ch.Conn.Close()
	if ch.Endpoint == nil || ch.Endpoint.Family != "sql" {
		return fmt.Errorf("clickhouse_native runtime invoked on non-sql endpoint %v", ch.Endpoint)
	}
	chEp, ok := ch.Endpoint.Body.(*ClickhouseNativeEndpoint)
	if !ok {
		return fmt.Errorf("clickhouse_native runtime invoked on non-native endpoint %v", ch.Endpoint)
	}
	upstreamAddr := chNativeUpstreamAddr(ch.Endpoint, chEp)
	if upstreamAddr == "" {
		return fmt.Errorf("clickhouse_native endpoint %q has no host", ch.Endpoint.Name)
	}

	// Step 1: read agent's Hello. ClickHouse's native protocol begins
	// with a single client Hello packet (type 0). We accumulate bytes
	// until parseHello succeeds — typical Hellos fit in one read but
	// large client_name strings can span multiple TCP segments.
	hello, leftover, err := chReadHello(ch.Conn)
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}

	// Step 2: resolve credential and inject. Single-credential native
	// endpoints today; multi-credential dispatch via placeholder lands
	// when SQL parsing does in iter 2.
	claimedUser := hello.Username
	injected := false
	if cc := chPickCredential(ch.Endpoint); cc != nil {
		if auth, ok := cc.Credential.Body.(runtime.ClickhouseAuthCredential); ok {
			sec, secErr := ch.Secrets.Get(cc.Credential.Symbol.Name, ch.Profile)
			if secErr == nil {
				realUser, realPassword := auth.ClickhouseAuth(sec)
				before := hello.Username + "\x00" + hello.Password
				if realUser != "" {
					hello.Username = realUser
				}
				if realPassword != "" {
					hello.Password = realPassword
				}
				if hello.Username+"\x00"+hello.Password != before {
					injected = true
				}
			} else {
				log.Printf("clickhouse_native %s: fetch secret %q: %v", ch.Endpoint.Name, cc.Credential.Symbol.Name, secErr)
			}
		}
	}

	// Step 3: dial upstream + send hello.
	upstream, err := ch.DialUpstream(ctx, "tcp", upstreamAddr)
	if err != nil {
		return fmt.Errorf("dial upstream %s: %w", upstreamAddr, err)
	}
	defer upstream.Close()

	if chEp.TLS {
		host := upstreamAddr
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		tc := tls.Client(upstream, &tls.Config{ServerName: host})
		if err := tc.Handshake(); err != nil {
			return fmt.Errorf("upstream tls: %w", err)
		}
		upstream = tc
	}

	rewritten := chSerializeHello(hello)
	if _, err := upstream.Write(rewritten); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	// Any bytes the agent sent past the Hello (rare — clients usually
	// wait for ServerHello before pipelining) follow immediately.
	if len(leftover) > 0 {
		if _, err := upstream.Write(leftover); err != nil {
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

// chPickCredential returns the (only) credential bound to the
// endpoint, or nil. Multi-credential dispatch by placeholder will
// move into the SQL-parsing iteration.
func chPickCredential(ep *config.CompiledEndpoint) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	return ep.Credentials[0]
}

func chNativeUpstreamAddr(ep *config.CompiledEndpoint, body *ClickhouseNativeEndpoint) string {
	for _, h := range ep.Hosts {
		if h == "" {
			continue
		}
		// ep.Hosts entries already carry the port from ConnRouteHosts.
		if _, _, err := net.SplitHostPort(h); err == nil {
			return h
		}
		return fmt.Sprintf("%s:%d", h, body.port())
	}
	return ""
}

func chHostPort(addr string) (string, int) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return h, 0
		}
		port = port*10 + int(c-'0')
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
			h, consumed, err := chParseHello(buf)
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

// chSerializeHello / chParseHello are thin wrappers over the protocol
// helpers in clickhouse_native_protocol.go.
func chSerializeHello(h ChHello) []byte             { return SerializeChHello(h) }
func chParseHello(buf []byte) (ChHello, int, error) { return ParseChHello(buf) }
