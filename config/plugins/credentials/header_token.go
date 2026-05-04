package credentials

// header_token: stamp the secret onto an arbitrary header, optionally
// prefixed (e.g. "Bearer ", "Token ").

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type HeaderToken struct {
	Header string `hcl:"header"`
	Prefix string `hcl:"prefix,optional"`
}

func (h *HeaderToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if h.Header == "" || len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set(h.Header, h.Prefix+string(sec.Bytes))
	return nil
}

func (*HeaderToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Header value"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*HeaderToken)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "header_token",
		New:     newer[HeaderToken](),
		Runtime: (*HeaderToken)(nil),
		Build:   passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*HeaderToken)
			b.SetAttributeValue("header", cty.StringVal(v.Header))
			if v.Prefix != "" {
				b.SetAttributeValue("prefix", cty.StringVal(v.Prefix))
			}
		},
	})
}
