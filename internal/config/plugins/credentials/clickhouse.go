package credentials

// clickhouse_credential: HTTPS API takes user + password as query
// params (?user=…&password=…) or basic-auth header. We populate both
// — basic-auth handles default-auth ClickHouse setups, query params
// handle setups that disable header auth.

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
	User     string `hcl:"user,optional"`
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
	q := req.URL.Query()
	q.Set("user", c.User)
	q.Set("password", password)
	req.URL.RawQuery = q.Encode()
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
