package credentials

// postgres_credential: the wire-protocol user the runtime uses when
// terminating upstream auth on the agent's behalf. User is the HCL
// field; password lives in the secret store under the credential's
// bare name (operator pastes via the dashboard's Postgres slot).

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// PostgresCredential is part of the clawpatrol plugin API.
//
// Database, when set, is the discriminator the dispatcher uses to
// pick this credential when several postgres_credential blocks bind
// the same endpoint(s). At request time the gateway reads the
// agent-declared database off the StartupMessage and picks the
// credential whose `database` matches; an unset `database` field is
// the catchall (one allowed per (profile, endpoint)).
type PostgresCredential struct {
	User     string `hcl:"user,optional"`
	Database string `hcl:"database,optional"`
}

// CredentialDatabase reports the operator-declared database
// discriminator for this credential. Retained for HCL emit / dump
// consumers; dispatch reads it through CredentialDisambiguators.
func (p *PostgresCredential) CredentialDatabase() string { return p.Database }

// CredentialDisambiguators implements
// config.CredentialDisambiguatorBody. `user` is the primary
// discriminator (postgres routes via StartupMessage.user);
// `database` is also supported when multiple credentials bind one
// endpoint with different default databases.
func (p *PostgresCredential) CredentialDisambiguators() map[string]string {
	out := map[string]string{}
	if p.User != "" {
		out["user"] = p.User
	}
	if p.Database != "" {
		out["database"] = p.Database
	}
	return out
}

// PostgresAuth implements runtime.PostgresAuthCredential — the
// postgres endpoint runtime calls this once per session to learn
// what (user, password) to use for upstream SCRAM / cleartext.
func (p *PostgresCredential) PostgresAuth(sec runtime.Secret) (string, string) {
	return p.User, string(sec.Bytes)
}

// SecretSlots is part of the clawpatrol plugin API.
func (*PostgresCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Postgres password"}}
}

func init() {
	var _ runtime.PostgresAuthCredential = (*PostgresCredential)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "postgres_credential",
		New:            newer[PostgresCredential](),
		Runtime:        (*PostgresCredential)(nil),
		Build:          passthrough,
		Disambiguators: []string{"user", "database"},
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*PostgresCredential)
			if v.User != "" {
				b.SetAttributeValue("user", cty.StringVal(v.User))
			}
			if v.Database != "" {
				b.SetAttributeValue("database", cty.StringVal(v.Database))
			}
		},
	})
}
