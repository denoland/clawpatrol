package credentials

// basic_auth: Authorization: Basic <base64(username:password)>.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// BasicAuth injects `Authorization: Basic <base64(username:password)>`.
//
// The credential secret is the raw password; `username` lives in
// config. Common credential binding fields apply: use `endpoint` or
// `endpoints` to bind the credential to upstreams.
//
// When a profile has multiple Basic Auth credentials for the same HTTPS
// endpoint, use the `placeholder` disambiguator on the profile entry or
// credential block. The HTTPS placeholder detector matches that value
// inside decoded `Authorization: Basic <base64(username:placeholder)>`
// request headers.
type BasicAuth struct {
	// Username is the upstream HTTP Basic Auth username.
	Username string `hcl:"username"`
}

// InjectHTTP is part of the clawpatrol plugin API.
func (b *BasicAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.SetBasicAuth(b.Username, string(sec.Bytes))
	return nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*BasicAuth) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Password", Description: "Stamped as `Authorization: Basic …` with the configured username."}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*BasicAuth)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "basic_auth",
		Disambiguators: []string{"placeholder"},
		New:            newer[BasicAuth](),
		Runtime:        (*BasicAuth)(nil),
		Build:          passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*BasicAuth)
			b.SetAttributeValue("username", cty.StringVal(v.Username))
		},
	})
}
