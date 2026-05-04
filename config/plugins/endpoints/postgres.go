package endpoints

// postgres endpoint: a single RDS-or-equivalent server. Postgres-
// specific runtime details (SCRAM helper, conn handler) live in
// postgres_runtime.go and postgres_auth.go alongside this file.

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// PostgresEndpoint addresses a single RDS-or-equivalent server.
// Tunnel topologies (kubectl-portforward-ssh and friends) aren't
// supported in this iteration — operators run the gateway with
// network reachability already arranged.
//
// SSLMode mirrors libpq's sslmode names — "disable" / "prefer" /
// "require" / "verify-full". Default "prefer": try TLS, fall back
// to plain when the upstream replies 'N'. "require" hard-fails on
// 'N'. "verify-full" additionally validates the upstream cert
// against Host. "disable" skips the SSLRequest probe entirely —
// fine for self-hosted pg on a private network where WG already
// encrypts the path.
type PostgresEndpoint struct {
	Host           string    `hcl:"host"`
	Database       string    `hcl:"database"`
	SSLMode        string    `hcl:"sslmode,optional"`
	Credential     string    `hcl:"credential,optional"`
	CredentialsRaw cty.Value `hcl:"credentials,optional" json:"-"`

	Credentials []CredentialEntry `json:"Credentials,omitempty"`
}

func (e *PostgresEndpoint) EndpointHosts() []string { return []string{e.Host} }
func (e *PostgresEndpoint) EndpointCredentials() []config.CredBinding {
	return bindings(e.Credential, e.Credentials)
}

func (e *PostgresEndpoint) credentialAndRaw() (string, cty.Value) {
	return e.Credential, e.CredentialsRaw
}
func (e *PostgresEndpoint) setCredentialEntries(es []CredentialEntry) { e.Credentials = es }

// PostgresEndpointRuntime detects placeholders in a postgres
// StartupMessage. The wire-protocol front-end populates Request with
// a SQL meta whose Statement field carries the agent's submitted
// password verbatim before injection.
type PostgresEndpointRuntime struct{}

func (PostgresEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.SQL == nil {
		return ""
	}
	hay := req.SQL.Statement
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

func init() {
	var _ runtime.PlaceholderDetector = PostgresEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "postgres",
		Family:   "sql",
		New:      func() any { return &PostgresEndpoint{} },
		Refs:     singularRef,
		Validate: multiCredValidate,
		Runtime:  PostgresEndpointRuntime{},
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*PostgresEndpoint)
			b.SetAttributeValue("host", cty.StringVal(e.Host))
			b.SetAttributeValue("database", cty.StringVal(e.Database))
			emitCredentialBinding(b, e.Credential, e.Credentials)
		},
	})
}
