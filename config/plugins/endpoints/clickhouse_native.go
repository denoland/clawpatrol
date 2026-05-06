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
// TLS toggles TLS on both hops: the gateway terminates the agent's
// TLS using a leaf minted off the gateway CA, parses the Hello in
// plaintext, then re-wraps to upstream. The wrapped client therefore
// keeps speaking native-over-TLS exactly as it would against the
// real cloud ClickHouse — `clawpatrol run` is transparent to its
// TLS posture. Default false: WG-only deployments where the operator
// wants plaintext on the inner hop (typical self-hosted ClickHouse
// on 9000 behind a private network) leave it off.
type ClickhouseNativeEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Port       int      `hcl:"port,optional"`
	TLS        bool     `hcl:"tls,optional"`
	Credential string   `hcl:"credential,optional"`
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
func (e *ClickhouseNativeEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

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
