package credentials

// notion_oauth: Bearer token in Authorization + Notion-Version header
// (Notion's API requires the version, defaults to a recent stable).

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// NotionOAuth is part of the clawpatrol plugin API.
type NotionOAuth struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (n *NotionOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	if req.Header.Get("Notion-Version") == "" {
		req.Header.Set("Notion-Version", "2022-06-28")
	}
	return nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*NotionOAuth) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Notion OAuth access token", Description: "secret_… integration token or OAuth access_token. Stamped as Authorization: Bearer + Notion-Version header."}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*NotionOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "notion_oauth",
		New:     newer[NotionOAuth](),
		Runtime: (*NotionOAuth)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
