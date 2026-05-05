package credentials

// openai_codex_oauth: bearer token for the codex CLI's OAuth flow.
// api.openai.com + chatgpt.com both accept Authorization: Bearer.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type OpenAICodexOAuth struct{}

func (a *OpenAICodexOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	// chatgpt.com's /backend-api/codex/responses endpoint returns 405
	// without the `chatgpt-account-id` header. The id is buried in the
	// access token's JWT claims (claims.chatgpt_account_id, or the
	// nested "https://api.openai.com/auth".chatgpt_account_id form).
	// Decode + stamp matching unclaw's openai-codex plugin behavior.
	if id := chatgptAccountID(string(sec.Bytes)); id != "" {
		req.Header.Set("chatgpt-account-id", id)
	}
	return nil
}

// chatgptAccountID extracts the chatgpt_account_id claim from an
// OpenAI-issued JWT (id_token or access_token). Returns empty string
// when the token isn't a JWT or the claim is missing — caller skips
// the header in that case.
func chatgptAccountID(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// JWTs sometimes ship with padding; try the URL-safe variant.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
		Auth             struct {
			ChatGPTAccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if claims.ChatGPTAccountID != "" {
		return claims.ChatGPTAccountID
	}
	return claims.Auth.ChatGPTAccountID
}

// EnvVars intentionally returns nothing.
//
// Codex env-var push-down lives on the openai_codex_https endpoint
// plugin (config/plugins/endpoints/openai_codex_https.go). Pushing it
// from the credential would attach the synthetic JWT to every
// endpoint that binds this credential — including api.openai.com,
// where it has no business going. Operators wire codex via:
//
//	credential "openai_codex_oauth" "codex" {}
//
//	endpoint "openai_codex_https" "codex" {
//	  hosts      = ["chatgpt.com"]
//	  credential = codex
//	}
func (*OpenAICodexOAuth) EnvVars() []config.EnvVar { return nil }

func (a *OpenAICodexOAuth) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		// Non-standard "openai_device" flow handled in oauth.go:
		// start hits deviceauth/usercode (JSON), poll hits
		// deviceauth/token (JSON, returns authorization_code +
		// code_verifier), then we exchange via /oauth/token.
		Flow: "openai_device",
		OAuth: config.OAuthConfig{
			// Codex CLI client_id — same as the desktop app uses, so
			// device-code prompts on auth.openai.com/codex/device
			// recognize the request.
			ClientID:     "app_EMoamEEZ73f0CkXaXp7hrann",
			DeviceURL:    "https://auth.openai.com/api/accounts/deviceauth/usercode",
			AuthURL:      "https://auth.openai.com/api/accounts/deviceauth/token",
			TokenURL:     "https://auth.openai.com/oauth/token",
			RedirectURI:  "https://auth.openai.com/deviceauth/callback",
			Scopes:       []string{"openid", "profile", "email", "offline_access"},
			RefreshToken: "{{secret:CODEX_REFRESH}}",
		},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*OpenAICodexOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "openai_codex_oauth",
		New:     newer[OpenAICodexOAuth](),
		Runtime: (*OpenAICodexOAuth)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
