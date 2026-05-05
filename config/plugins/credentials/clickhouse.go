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

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type ClickhouseCredential struct {
	User string `hcl:"user,optional"`
}

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

func (*ClickhouseCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "ClickHouse password"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*ClickhouseCredential)(nil)
	var _ runtime.ClickhouseAuthCredential = (*ClickhouseCredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "clickhouse_credential",
		New:     newer[ClickhouseCredential](),
		Runtime: (*ClickhouseCredential)(nil),
		Build:   passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*ClickhouseCredential)
			if v.User != "" {
				b.SetAttributeValue("user", cty.StringVal(v.User))
			}
		},
	})
}
