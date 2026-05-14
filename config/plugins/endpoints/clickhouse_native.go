package endpoints

// clickhouse_native endpoint: ClickHouse's binary native protocol
// (default port 9000 plaintext / 9440 TLS). Pairs with
// clickhouse_https for the same upstream cluster.
//
// Iter 1 scope: parse the Hello packet, swap placeholder bytes in
// the agent-supplied (username, password) for the credential's real
// values, emit one connection event, then transparent bidirectional
// pipe. SQL parsing lands in a follow-up iteration.
//
// Schema and HCL plumbing live here. The per-connection runtime
// (HandleConn, helpers, pipe) lives in clickhouse_native_runtime.go.

import (
	"fmt"
	"net"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	sqlfacet "github.com/denoland/clawpatrol/config/plugins/facets/sql"
	"github.com/denoland/clawpatrol/config/runtime"
)

// ClickhouseNativeEndpoint addresses one ClickHouse server reachable
// via the binary native protocol. Operators bind a single
// clickhouse_credential; the runtime parses the agent's Hello and
// substitutes the credential's (user, password) where the agent
// embedded a placeholder.
//
// TLS toggles TLS on both hops: the gateway terminates the agent's
// TLS using a leaf minted off the gateway CA, parses the Hello in
// plaintext, then re-wraps to upstream. The wrapped client therefore
// keeps speaking native-over-TLS exactly as it would against the
// real cloud ClickHouse — `clawpatrol run` is transparent to its
// TLS posture. Default false: WG-only deployments where the operator
// wants plaintext on the inner hop (typical self-hosted ClickHouse
// on 9000 behind a private network) leave it off.
//
// AcceptInvalidCertificate mirrors clickhouse-client's flag of the
// same name: when true and tls is on, the gateway skips upstream cert
// validation. Use for self-hosted ClickHouse fronted by a private CA.
// Default false keeps full validation against system roots.
// Database, when set, restricts this endpoint to connections whose
// agent-declared database (Hello.Database) equals the configured
// value. Unset = catch-all: the endpoint claims connections to its
// host regardless of database, which preserves the v1 single-endpoint
// behavior. Specific beats catch-all when both are bound to the same
// host (the dispatcher reads Hello before picking).
type ClickhouseNativeEndpoint struct {
	Hosts                    []string `hcl:"hosts"`
	Port                     int      `hcl:"port,optional"`
	TLS                      bool     `hcl:"tls,optional"`
	AcceptInvalidCertificate bool     `hcl:"accept_invalid_certificate,optional"`
	Database                 string   `hcl:"database,optional"`
	Credential               string   `hcl:"credential,optional"`
}

// EndpointHosts returns the endpoint's host:port list, normalized so
// every entry carries an explicit port. The dnsvip allocator and
// runtime helpers both consume this; emitting host:port everywhere
// lets a single endpoint mix bare hostnames and host:port literals
// in HCL without the plugin or dnsvip having to special-case the
// "default port" rule.
func (e *ClickhouseNativeEndpoint) EndpointHosts() []string {
	port := e.port()
	out := make([]string, 0, len(e.Hosts))
	for _, h := range e.Hosts {
		if _, _, err := net.SplitHostPort(h); err == nil {
			out = append(out, h)
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d", h, port))
	}
	return out
}

// EndpointCredentials is part of the clawpatrol plugin API.
func (e *ClickhouseNativeEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

// DispatchDatabase opts the endpoint into the compile-time
// database-routing uniqueness check (config.DatabaseRouter). The
// runtime reads the value via the same accessor when picking among
// candidate endpoints that share a host.
func (e *ClickhouseNativeEndpoint) DispatchDatabase() string { return e.Database }

// RequiresVIP opts the endpoint into DNS-VIP interception. The wire
// protocol carries no SNI / Host header, so the gateway can't
// dispatch on dst IP alone — dnsvip allocates a stable VIP per
// hostname at policy build, intercepts the agent's DNS query for
// that hostname, and the WG forwarder routes the resulting traffic
// to handleVIPConn → this plugin's HandleConn.
func (e *ClickhouseNativeEndpoint) RequiresVIP() bool { return true }

// ConnRouteHosts mirrors EndpointHosts so every host lands in the
// gateway's conn-index. Hostname entries reach HandleConn through the
// VIP path (RequiresVIP=true allocates a per-host VIP); IP-literal
// entries are skipped by dnsvip — there's no DNS query to intercept —
// and reach HandleConn through the WG forwarder's direct-IP dispatch,
// which keys off this index.
func (e *ClickhouseNativeEndpoint) ConnRouteHosts() []string {
	return e.EndpointHosts()
}

func (e *ClickhouseNativeEndpoint) port() int {
	if e.Port > 0 {
		return e.Port
	}
	if e.TLS {
		return 9440
	}
	return 9000
}

// ClickhouseNativeEndpointRuntime is the per-connection handler.
// Stateless — all per-session state lives on ConnHandle.
// HandleConn is implemented in clickhouse_native_runtime.go.
type ClickhouseNativeEndpointRuntime struct{}

// ParseStatement satisfies runtime.SQLParser so the action-fixture
// loader can populate match.Request.Meta from a raw statement using
// the same AST extractor live dispatch uses.
func (ClickhouseNativeEndpointRuntime) ParseStatement(sql string) any {
	info := parseChSQL(sql)
	return &sqlfacet.Meta{
		Verb:      info.Verb,
		Tables:    info.Tables,
		Functions: info.Functions,
		Statement: info.Statement,
	}
}

func init() {
	var _ runtime.ConnEndpointRuntime = ClickhouseNativeEndpointRuntime{}
	var _ runtime.SQLParser = ClickhouseNativeEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "clickhouse_native",
		Family:   "sql",
		New:      func() any { return &ClickhouseNativeEndpoint{} },
		Refs:     singularRef,
		Runtime:  ClickhouseNativeEndpointRuntime{},
		Validate: validateClickhouseNativeEndpoint,
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*ClickhouseNativeEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			if e.Port > 0 {
				b.SetAttributeValue("port", cty.NumberIntVal(int64(e.Port)))
			}
			if e.TLS {
				b.SetAttributeValue("tls", cty.BoolVal(true))
			}
			if e.AcceptInvalidCertificate {
				b.SetAttributeValue("accept_invalid_certificate", cty.BoolVal(true))
			}
			if e.Database != "" {
				b.SetAttributeValue("database", cty.StringVal(e.Database))
			}
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}

// pickClickhouseNativeByDatabase chooses an endpoint from a set of
// clickhouse_native candidates whose Database fields disagree.
// Candidates are the same-host siblings the dispatcher saw at
// dispatch time; database is Hello.Database read from the agent's
// session-startup packet. Precedence: a candidate whose Database
// equals database wins; otherwise the catch-all (Database == "")
// wins. Returns nil when the input is empty OR when there is no
// catch-all and no specific match — the dispatcher then refuses the
// connection rather than silently routing through an unrelated
// endpoint. The compile pass already rejected duplicate (host,
// Database) pairs, so the picked endpoint is unambiguous.
func pickClickhouseNativeByDatabase(candidates []*config.CompiledEndpoint, database string) *config.CompiledEndpoint {
	if len(candidates) == 0 {
		return nil
	}
	var catchAll *config.CompiledEndpoint
	for _, c := range candidates {
		if c == nil {
			continue
		}
		body, ok := c.Body.(*ClickhouseNativeEndpoint)
		if !ok {
			continue
		}
		if body.Database == "" {
			if catchAll == nil {
				catchAll = c
			}
			continue
		}
		if body.Database == database {
			return c
		}
	}
	return catchAll
}

// validateClickhouseNativeEndpoint rejects accept_invalid_certificate
// when tls is off — the flag only affects the upstream TLS handshake,
// so without tls there's nothing for it to do.
func validateClickhouseNativeEndpoint(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	e, ok := d.(*ClickhouseNativeEndpoint)
	if !ok {
		return nil
	}
	if e.AcceptInvalidCertificate && !e.TLS {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("accept_invalid_certificate set without tls on clickhouse_native endpoint %q", name),
			Detail:   "accept_invalid_certificate only affects the upstream TLS handshake; set `tls = true` to enable TLS, or remove accept_invalid_certificate.",
			Subject:  &ctx.Block.DefRange,
		}}
	}
	return nil
}
