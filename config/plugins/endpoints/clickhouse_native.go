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
//
// Hosts may be supplied as bare hostnames or as host:port literals.
// The bare form is normalized to host:e.port(); the host:port form
// is preserved verbatim, so an operator binding a cluster on mixed
// ports gets the literal each member declared rather than a
// silently-double-suffixed `host:port:port`.
func (e *ClickhouseNativeEndpoint) ConnRouteHosts() []string {
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

func (e *ClickhouseNativeEndpoint) port() int {
	if e.Port > 0 {
		return e.Port
	}
	return 9000
}

// ClickhouseNativeEndpointRuntime is the per-connection handler.
// Stateless — all per-session state lives on ConnHandle.
// HandleConn is implemented in clickhouse_native_runtime.go.
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
