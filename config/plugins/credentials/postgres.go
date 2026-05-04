package credentials

// postgres_credential: the wire-protocol user the runtime uses when
// terminating upstream auth on the agent's behalf. User is the HCL
// field; password lives in the secret store under the credential's
// bare name (operator pastes via the dashboard's Postgres slot).

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type PostgresCredential struct {
	User string `hcl:"user,optional"`
}

// PostgresAuth implements runtime.PostgresAuthCredential — the
// postgres endpoint runtime calls this once per session to learn
// what (user, password) to use for upstream SCRAM / cleartext.
func (p *PostgresCredential) PostgresAuth(sec runtime.Secret) (string, string) {
	return p.User, string(sec.Bytes)
}

func (*PostgresCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Postgres password"}}
}

func init() {
	var _ runtime.PostgresAuthCredential = (*PostgresCredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "postgres_credential",
		New:     newer[PostgresCredential](),
		Runtime: (*PostgresCredential)(nil),
		Build:   passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*PostgresCredential)
			if v.User != "" {
				b.SetAttributeValue("user", cty.StringVal(v.User))
			}
		},
	})
}
