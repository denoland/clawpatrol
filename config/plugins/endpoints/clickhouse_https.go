package endpoints

// clickhouse_https endpoint: HTTPS API surface for ClickHouse. Pairs
// with clickhouse_native (same upstream cluster, different protocol)
// so rules can target both via `endpoints = [ch-https, ch-native]`.

import (
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
)

type ClickhouseHTTPSEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Credential string   `hcl:"credential,optional"`
}

func (e *ClickhouseHTTPSEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *ClickhouseHTTPSEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

func init() {
	config.Register(&config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   "clickhouse_https",
		Family: "sql",
		New:    func() any { return &ClickhouseHTTPSEndpoint{} },
		Refs:   singularRef,
		Build:  passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*ClickhouseHTTPSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}
