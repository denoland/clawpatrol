package credentials

// notion_oauth: Bearer token in Authorization + Notion-Version header
// (Notion's API requires the version, defaults to a recent stable).

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type NotionOAuth struct{}

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
