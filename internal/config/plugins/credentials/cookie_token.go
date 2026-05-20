package credentials

// cookie_token: stamp the secret as an HTTP cookie under the
// configured name.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// CookieToken is part of the clawpatrol plugin API.
type CookieToken struct {
	// CookieName is the HTTP cookie name that receives the secret value.
	CookieName string `hcl:"cookie_name,optional"`
}

// InjectHTTP is part of the clawpatrol plugin API.
func (c *CookieToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if c.CookieName == "" || len(sec.Bytes) == 0 {
		return nil
	}
	req.AddCookie(&http.Cookie{Name: c.CookieName, Value: string(sec.Bytes)})
	return nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*CookieToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Cookie value"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*CookieToken)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "cookie_token",
		Disambiguators: []string{"placeholder"},
		New:            newer[CookieToken](),
		Runtime:        (*CookieToken)(nil),
		Build:          passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*CookieToken)
			if v.CookieName != "" {
				b.SetAttributeValue("cookie_name", cty.StringVal(v.CookieName))
			}
		},
	})
}
