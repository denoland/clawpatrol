package credentials

// bearer_token: Authorization: Bearer <secret>. Optional
// idempotency_key flag stamps a derived Idempotency-Key header on
// writes when the agent didn't already.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type BearerToken struct {
	IdempotencyKey bool `hcl:"idempotency_key,optional"`
}

func (b *BearerToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	if b.IdempotencyKey && req.Method != http.MethodGet && req.Method != http.MethodHead {
		// Stripe-style: stamp Idempotency-Key on writes if the agent
		// didn't already. Value derives from the request's idempotency
		// hint header so retries collapse but distinct requests don't.
		if req.Header.Get("Idempotency-Key") == "" {
			req.Header.Set("Idempotency-Key", idempotencyKeyFor(req))
		}
	}
	return nil
}

// idempotencyKeyFor returns a deterministic key derived from the
// agent's idempotency hint. Falls back to method+path when the agent
// didn't set one.
func idempotencyKeyFor(req *http.Request) string {
	if k := req.Header.Get("X-Clawpatrol-Idempotency-Hint"); k != "" {
		return k
	}
	return req.URL.Path + "@" + req.Method
}

func (*BearerToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Bearer token", Description: "Stamped as `Authorization: Bearer …`."}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*BearerToken)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "bearer_token",
		New:     newer[BearerToken](),
		Runtime: (*BearerToken)(nil),
		Build:   passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*BearerToken)
			if v.IdempotencyKey {
				b.SetAttributeValue("idempotency_key", cty.True)
			}
		},
	})
}
