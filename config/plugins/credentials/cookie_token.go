package credentials

// cookie_token: stamp the secret as an HTTP cookie under the
// configured name.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type CookieToken struct {
	CookieName string `hcl:"cookie_name,optional"`
}

func (c *CookieToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if c.CookieName == "" || len(sec.Bytes) == 0 {
		return nil
	}
	req.AddCookie(&http.Cookie{Name: c.CookieName, Value: string(sec.Bytes)})
	return nil
}

func (*CookieToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Cookie value"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*CookieToken)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "cookie_token",
		New:     newer[CookieToken](),
		Runtime: (*CookieToken)(nil),
		Build:   passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*CookieToken)
			if v.CookieName != "" {
				b.SetAttributeValue("cookie_name", cty.StringVal(v.CookieName))
			}
		},
	})
}
