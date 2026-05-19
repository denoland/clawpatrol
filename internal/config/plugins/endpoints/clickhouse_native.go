package endpoints

// clickhouse_native endpoint: ClickHouse's binary native protocol
// (default port 9000 plaintext / 9440 TLS). Pairs with
// clickhouse_https for the same upstream cluster.
//
// On each connection the runtime parses the Hello packet, swaps
// placeholder bytes in the agent-supplied (username, password) for
// the credential's real values, parses each Query packet's SQL for
// rule matching, then bidirectionally pipes between agent and server.
//
// Schema and HCL plumbing live here. The per-connection runtime
// (HandleConn, helpers, pipe) lives in clickhouse_native_runtime.go.

import (
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	sqlfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
	"github.com/denoland/clawpatrol/internal/config/runtime"
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
type ClickhouseNativeEndpoint struct {
	Hosts                    []string  `hcl:"hosts"`
	Port                     int       `hcl:"port,optional"`
	TLS                      bool      `hcl:"tls,optional"`
	AcceptInvalidCertificate bool      `hcl:"accept_invalid_certificate,optional"`
	Credential               string    `hcl:"credential,optional"`
	CredentialsRaw           cty.Value `hcl:"credentials,optional" json:"-"`

	Credentials []CredentialEntry `json:"Credentials,omitempty"`
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
	return bindings(e.Credential, e.Credentials)
}

func (e *ClickhouseNativeEndpoint) credentialAndRaw() (string, cty.Value) {
	return e.Credential, e.CredentialsRaw
}
func (e *ClickhouseNativeEndpoint) setCredentialEntries(es []CredentialEntry) { e.Credentials = es }

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
func (ClickhouseNativeEndpointRuntime) ParseStatement(sql string) (any, bool) {
	info, unparseable := parseChSQL(sql)
	return &sqlfacet.Meta{
		Verb:      info.Verb,
		Tables:    info.Tables,
		Functions: info.Functions,
		Statement: info.Statement,
	}, unparseable
}

// DetectPlaceholder scans the agent's Hello (username + password) for
// any candidate placeholder substring and returns the first match.
// The clickhouse_native runtime constructs a partial match.Request
// whose Meta.Statement carries `username + "\x00" + password` for
// detector consumption — same shape postgres uses.
func (ClickhouseNativeEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil {
		return ""
	}
	meta, _ := req.Meta.(*sqlfacet.Meta)
	if meta == nil {
		return ""
	}
	hay := meta.Statement
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

func init() {
	var _ runtime.ConnEndpointRuntime = ClickhouseNativeEndpointRuntime{}
	var _ runtime.SQLParser = ClickhouseNativeEndpointRuntime{}
	var _ runtime.PlaceholderDetector = ClickhouseNativeEndpointRuntime{}
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
			emitCredentialBinding(b, e.Credential, e.Credentials, "placeholder")
		},
	})
}

// validateClickhouseNativeEndpoint rejects accept_invalid_certificate
// when tls is off — the flag only affects the upstream TLS handshake,
// so without tls there's nothing for it to do — and additionally
// runs the shared multi-credential validator (the credentials list
// shape is the same as postgres / https).
func validateClickhouseNativeEndpoint(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	var diags hcl.Diagnostics
	e, ok := d.(*ClickhouseNativeEndpoint)
	if !ok {
		return nil
	}
	if e.AcceptInvalidCertificate && !e.TLS {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("accept_invalid_certificate set without tls on clickhouse_native endpoint %q", name),
			Detail:   "accept_invalid_certificate only affects the upstream TLS handshake; set `tls = true` to enable TLS, or remove accept_invalid_certificate.",
			Subject:  &ctx.Block.DefRange,
		})
	}
	diags = append(diags, multiCredValidate(d, name, ctx)...)
	return diags
}
