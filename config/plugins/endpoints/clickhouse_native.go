package endpoints

// clickhouse_native endpoint: ClickHouse's binary native protocol
// (default port 9000). Pairs with clickhouse_https for the same
// upstream cluster.

import (
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
)

type ClickhouseNativeEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Credential string   `hcl:"credential,optional"`
}

func (e *ClickhouseNativeEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *ClickhouseNativeEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

func init() {
	config.Register(&config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   "clickhouse_native",
		Family: "sql",
		New:    func() any { return &ClickhouseNativeEndpoint{} },
		Refs:   singularRef,
		Build:  passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*ClickhouseNativeEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}
