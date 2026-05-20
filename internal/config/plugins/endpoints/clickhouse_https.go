package endpoints

// clickhouse_https endpoint: HTTPS API surface for ClickHouse. Pairs
// with clickhouse_native (same upstream cluster, different protocol)
// so rules can target both via `endpoints = [ch-https, ch-native]`.

import (
	"net/http"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// ClickhouseHTTPSEndpoint is part of the clawpatrol plugin API.
type ClickhouseHTTPSEndpoint struct {
	Hosts []string `hcl:"hosts"`
}

// EndpointHosts is part of the clawpatrol plugin API.
func (e *ClickhouseHTTPSEndpoint) EndpointHosts() []string { return e.Hosts }

// ClickhouseHTTPSEndpointRuntime is the per-request handler. The
// HTTPS MITM loop runs the request through this runtime's
// PlaceholderDetector when an endpoint has a multi-credential
// dispatch binding.
type ClickhouseHTTPSEndpointRuntime struct{}

// DetectPlaceholder scans the agent's request for a placeholder
// substring. ClickHouse HTTPS clients put credentials in the
// Authorization header (Basic), in the `?user=` / `?password=`
// query params, or in `X-ClickHouse-User` / `X-ClickHouse-Key`
// headers. We scan all of them and return the first candidate found.
func (ClickhouseHTTPSEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil {
		return ""
	}
	var hay strings.Builder
	if req.Headers != nil {
		hay.WriteString(req.Headers.Get("Authorization"))
		hay.WriteByte(0)
		hay.WriteString(basicAuthPayload(req.Headers.Get("Authorization")))
		hay.WriteByte(0)
		hay.WriteString(req.Headers.Get("X-ClickHouse-User"))
		hay.WriteByte(0)
		hay.WriteString(req.Headers.Get("X-ClickHouse-Key"))
		hay.WriteByte(0)
	}
	if req.URL != nil {
		q := req.URL.Query()
		hay.WriteString(q.Get("user"))
		hay.WriteByte(0)
		hay.WriteString(q.Get("password"))
	}
	s := hay.String()
	for _, c := range candidates {
		if c != "" && strings.Contains(s, c) {
			return c
		}
	}
	return ""
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
	var _ runtime.PlaceholderDetector = ClickhouseHTTPSEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:    config.KindEndpoint,
		Type:    "clickhouse_https",
		Family:  "sql",
		New:     func() any { return &ClickhouseHTTPSEndpoint{} },
		Runtime: ClickhouseHTTPSEndpointRuntime{},
		Build:   passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*ClickhouseHTTPSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
		},
	})
}
