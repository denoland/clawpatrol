package endpoints

// clickhouse_https endpoint: HTTPS API surface for ClickHouse. Pairs
// with clickhouse_native (same upstream cluster, different protocol)
// so rules can target both via `endpoints = [ch-https, ch-native]`.

import (
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

// ClickhouseHTTPSEndpoint is part of the clawpatrol plugin API.
//
// Database, when set, restricts this endpoint to requests whose
// agent-declared database (the `database` URL query parameter or
// `X-ClickHouse-Database` header, query wins when both are set)
// equals the configured value. Unset = catch-all: the endpoint claims
// every request to its host regardless of database. Specific beats
// catch-all when both are bound to the same host.
type ClickhouseHTTPSEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Database   string   `hcl:"database,optional"`
	Credential string   `hcl:"credential,optional"`
}

// EndpointHosts is part of the clawpatrol plugin API.
func (e *ClickhouseHTTPSEndpoint) EndpointHosts() []string { return e.Hosts }

// EndpointCredentials is part of the clawpatrol plugin API.
func (e *ClickhouseHTTPSEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

// DispatchDatabase opts the endpoint into the compile-time
// database-routing uniqueness check (config.DatabaseRouter).
func (e *ClickhouseHTTPSEndpoint) DispatchDatabase() string { return e.Database }

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

// PickClickhouseHTTPSEndpointByDatabase chooses an endpoint from a
// set of clickhouse_https candidates whose Database fields disagree.
// Precedence: a candidate whose Database matches db exactly wins
// over a catch-all (Database == ""). When no specific candidate
// matches, the catch-all is returned. Returns nil only when the
// input is empty.
//
// Callers — once the HTTPS MITM request loop wires
// clickhouse_https endpoints — pass every endpoint that claims the
// SNI'd host (typically from a per-host candidate list built at
// policy compile time) and the request's database, computed via
// ClickhouseHTTPSDatabaseFromRequest.
func PickClickhouseHTTPSEndpointByDatabase(candidates []*ClickhouseHTTPSEndpoint, db string) *ClickhouseHTTPSEndpoint {
	if len(candidates) == 0 {
		return nil
	}
	var catchAll *ClickhouseHTTPSEndpoint
	for _, c := range candidates {
		if c == nil {
			continue
		}
		if c.Database == "" {
			if catchAll == nil {
				catchAll = c
			}
			continue
		}
		if c.Database == db {
			return c
		}
	}
	return catchAll
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
			if e.Database != "" {
				b.SetAttributeValue("database", cty.StringVal(e.Database))
			}
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}
