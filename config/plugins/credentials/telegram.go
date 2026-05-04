package credentials

// telegram_bot_token: bot token lives in the URL path
// (/bot<TOKEN>/<METHOD>) and sometimes in the request body
// (setWebhook posts a URL containing the token). We swap every
// occurrence of the operator-emitted placeholder with the real secret
// — operator's CLI uses the placeholder verbatim; gateway substitutes
// globally so the token never hits the upstream as the placeholder
// and never leaks to logs.
//
// Telegram doesn't appear in `clawpatrol env` because Telegram SDKs
// take the token as an explicit argument rather than reading it from
// the env, so there's nothing to "push down".

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// telegramPlaceholder is the bot-token placeholder operators put in
// their SDK config / URL when running through the gateway.
const telegramPlaceholder = "0000000000:clawpatrol-placeholder-do-not-use"

type TelegramBotToken struct{}

func (t *TelegramBotToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 || req.URL == nil {
		return nil
	}
	real := string(sec.Bytes)
	swap := func(s string) string {
		return strings.ReplaceAll(s, telegramPlaceholder, real)
	}

	if strings.Contains(req.URL.Path, telegramPlaceholder) {
		req.URL.Path = swap(req.URL.Path)
		// Drop the encoded form so http.Client re-encodes from .Path.
		req.URL.RawPath = ""
	}
	if strings.Contains(req.URL.RawQuery, telegramPlaceholder) {
		req.URL.RawQuery = swap(req.URL.RawQuery)
	}

	if req.Body != nil && req.Body != http.NoBody {
		buf, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return err
		}
		if bytes.Contains(buf, []byte(telegramPlaceholder)) {
			buf = bytes.ReplaceAll(buf, []byte(telegramPlaceholder), sec.Bytes)
		}
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
	}
	return nil
}

func (*TelegramBotToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Telegram bot token"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*TelegramBotToken)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "telegram_bot_token",
		New:     newer[TelegramBotToken](),
		Runtime: (*TelegramBotToken)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
