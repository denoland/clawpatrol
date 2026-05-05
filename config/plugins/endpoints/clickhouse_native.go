package endpoints

// clickhouse_native endpoint: ClickHouse's TLS-wrapped binary native
// protocol (default port 9440). Pairs with clickhouse_https for the same
// upstream cluster.

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

type ClickhouseNativeEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Port       int      `hcl:"port,optional" json:"Port,omitempty"`
	Credential string   `hcl:"credential,optional"`
}

func (e *ClickhouseNativeEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *ClickhouseNativeEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}
func (e *ClickhouseNativeEndpoint) NativePort() int {
	if e.Port != 0 {
		return e.Port
	}
	return 9440
}
func (e *ClickhouseNativeEndpoint) ConnRouteHosts() []string {
	out := make([]string, 0, len(e.Hosts))
	for _, h := range e.Hosts {
		if h == "" {
			continue
		}
		out = append(out, h)
	}
	return out
}

func init() {
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
			if e.Port != 0 {
				b.SetAttributeValue("port", cty.NumberIntVal(int64(e.Port)))
			}
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}
