package endpoints

// clickhouse_https endpoint: HTTPS API surface for ClickHouse. Pairs
// with clickhouse_native (same upstream cluster, different protocol)
// so rules can target both via `endpoints = [ch-https, ch-native]`.

import (
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
)

// ClickhouseHTTPSEndpoint is part of the clawpatrol plugin API.
type ClickhouseHTTPSEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Credential string   `hcl:"credential,optional"`
}

// EndpointHosts is part of the clawpatrol plugin API.
func (e *ClickhouseHTTPSEndpoint) EndpointHosts() []string { return e.Hosts }

// EndpointCredentials is part of the clawpatrol plugin API.
func (e *ClickhouseHTTPSEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

// ClickhouseHTTPSDatabaseFromRequest extracts the agent-declared
// database from a ClickHouse HTTPS request. ClickHouse accepts the
// target database two ways: the `database` URL query parameter or
// the `X-ClickHouse-Database` header; the query parameter takes
// precedence when both are set, mirroring clickhouse-server's own
// resolution order. Returns "" when neither is set.
func ClickhouseHTTPSDatabaseFromRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil {
		if v := req.URL.Query().Get("database"); v != "" {
			return v
		}
	}
	if req.Header != nil {
		if v := req.Header.Get("X-ClickHouse-Database"); v != "" {
			return v
		}
	}
	return ""
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
