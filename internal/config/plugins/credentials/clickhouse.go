package credentials

// clickhouse_credential: the HTTPS API accepts user + password as a
// basic-auth header or as ?user=…&password=… query params. Only the
// header is used: a secret in the URL ends up in access and proxy
// logs, so any query copy (placeholder or not) is stripped.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// ClickhouseCredential is part of the clawpatrol plugin API.
//
// Database, when set, is the discriminator the dispatcher uses to
// pick this credential when several clickhouse_credential blocks
// bind the same endpoint(s). At request time the gateway reads the
// agent-declared database off the wire and picks the credential
// whose `database` matches; an unset `database` field is the
// catchall (one allowed per (profile, endpoint)).
type ClickhouseCredential struct {
	// User is the upstream ClickHouse user the gateway injects.
	User string `hcl:"user,optional"`
	// Database limits this credential to ClickHouse requests for that
	// database. Empty acts as the catchall.
	Database string `hcl:"database,optional"`
}

// CredentialDatabase reports the operator-declared database
// discriminator for this credential. Retained for HCL emit / dump
// consumers; dispatch reads it through CredentialDisambiguators.
func (c *ClickhouseCredential) CredentialDatabase() string { return c.Database }

// CredentialDisambiguators implements
// config.CredentialDisambiguatorBody. ClickHouse supports both
// `database` and `user` discriminators — the operator can pick
// either or both depending on how their cluster is sliced.
func (c *ClickhouseCredential) CredentialDisambiguators() map[string]string {
	out := map[string]string{}
	if c.Database != "" {
		out["database"] = c.Database
	}
	if c.User != "" {
		out["user"] = c.User
	}
	return out
}

// InjectHTTP is part of the clawpatrol plugin API.
func (c *ClickhouseCredential) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if c.User == "" || len(sec.Bytes) == 0 || req.URL == nil {
		return nil
	}
	password := string(sec.Bytes)
	req.SetBasicAuth(c.User, password)
	// Auth goes in the header only. ClickHouse accepts ?user=&password=
	// too, but a secret in the URL ends up in upstream access logs,
	// proxy logs and error strings. Strip any copy the agent sent so a
	// placeholder never reaches the server either.
	if q := req.URL.Query(); q.Has("user") || q.Has("password") {
		q.Del("user")
		q.Del("password")
		req.URL.RawQuery = q.Encode()
	}
	// The X-ClickHouse-User / X-ClickHouse-Key placeholder form must go
	// too: ClickHouse rejects a request that carries those headers and
	// an Authorization header at the same time.
	req.Header.Del("X-ClickHouse-User")
	req.Header.Del("X-ClickHouse-Key")
	return nil
}

// ClickhouseAuth implements runtime.ClickhouseAuthCredential — the
// clickhouse_native endpoint runtime calls this once per session to
// learn what (user, password) to substitute into the Hello packet.
func (c *ClickhouseCredential) ClickhouseAuth(sec runtime.Secret) (string, string) {
	return c.User, string(sec.Bytes)
}

// SecretSlots is part of the clawpatrol plugin API.
func (*ClickhouseCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "ClickHouse password"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*ClickhouseCredential)(nil)
	var _ runtime.ClickhouseAuthCredential = (*ClickhouseCredential)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "clickhouse_credential",
		New:            newer[ClickhouseCredential](),
		Runtime:        (*ClickhouseCredential)(nil),
		Build:          passthrough,
		Disambiguators: []string{"database", "user"},
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*ClickhouseCredential)
			if v.User != "" {
				b.SetAttributeValue("user", cty.StringVal(v.User))
			}
			if v.Database != "" {
				b.SetAttributeValue("database", cty.StringVal(v.Database))
			}
		},
	})
}
