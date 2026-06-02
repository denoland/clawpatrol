package credentials

// header_token: stamp the secret onto an arbitrary header, optionally
// prefixed (e.g. "Bearer ", "Token ").

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// HeaderToken is part of the clawpatrol plugin API.
type HeaderToken struct {
	// Header is the HTTP header name to overwrite with the secret value.
	Header string `hcl:"header"`
	// Prefix is prepended to the secret before injection, for schemes
	// such as "Bearer " or "Token ".
	Prefix string `hcl:"prefix,optional"`
}

// InjectHTTP is part of the clawpatrol plugin API.
func (h *HeaderToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if h.Header == "" || len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set(h.Header, h.Prefix+string(sec.Bytes))
	return nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*HeaderToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Header value"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*HeaderToken)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "header_token",
		Disambiguators: []string{"placeholder"},
		New:            newer[HeaderToken](),
		Runtime:        (*HeaderToken)(nil),
		Build:          passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*HeaderToken)
			b.SetAttributeValue("header", cty.StringVal(v.Header))
			if v.Prefix != "" {
				b.SetAttributeValue("prefix", cty.StringVal(v.Prefix))
			}
		},
	})
}
