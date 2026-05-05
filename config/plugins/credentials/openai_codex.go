package credentials

// openai_codex_oauth: bearer token for the codex CLI's OAuth flow.
// api.openai.com + chatgpt.com both accept Authorization: Bearer.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
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

// EnvVars pushes a synthetic CODEX_ACCESS_TOKEN (Agent Identity JWT
// signed by clawpatrol) plus a redirect for the agent-identity API
// base URL. Both bypass the OPENAI_API_KEY codepath that would
// otherwise route codex to api.openai.com — the synthetic JWT puts
// codex into AgentIdentity mode and points it at chatgpt.com, where
// the existing chatgpt.com binding swaps Authorization +
// chatgpt-account-id for the user's real subscription bearer.
//
// The JWT validates against a JWKS clawpatrol serves locally (see
// RespondHTTP below) since clawpatrol owns chatgpt.com's TLS via
// MITM. Task registration is similarly stubbed locally — pushing
// CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL to chatgpt.com keeps that
// call on a host we already terminate, instead of leaking to
// auth.openai.com (codex's default).
func (*OpenAICodexOAuth) EnvVars() []config.EnvVar {
	jwt, err := MintCodexAccessToken()
	if err != nil {
		// Fall back silently — without the JWT codex goes through its
		// real auth.json and clawpatrol's MITM still works for users
		// who already ran `codex login`. The error surfaces in
		// `clawpatrol env`'s stderr via the caller's logging.
		return nil
	}
	return []config.EnvVar{
		{
			Name:        "CODEX_ACCESS_TOKEN",
			Value:       jwt,
			Description: "synthetic Agent Identity JWT — routes codex ≥ 0.129 to chatgpt.com",
		},
		{
			// Codex 0.128 and earlier read the JWT from
			// CODEX_AGENT_IDENTITY; the rename to CODEX_ACCESS_TOKEN
			// landed post-0.128 (codex commit 0d418f478d). Set both so
			// clawpatrol works across versions; whichever the
			// installed codex looks for wins.
			Name:        "CODEX_AGENT_IDENTITY",
			Value:       jwt,
			Description: "synthetic Agent Identity JWT — routes codex ≤ 0.128 to chatgpt.com",
		},
		{
			Name:        "CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL",
			Value:       "https://chatgpt.com/backend-api/wham",
			Description: "keeps agent-task registration on a host clawpatrol MITMs",
		},
	}
}

// RespondHTTP intercepts the two chatgpt.com paths codex hits during
// Agent Identity init: the JWKS that validates the synthetic JWT and
// the agent-task registration POST that returns a task_id. Both are
// served from clawpatrol-controlled state — neither reaches the real
// chatgpt.com.
func (a *OpenAICodexOAuth) RespondHTTP(_ context.Context, req *http.Request, _ runtime.Secret) (*http.Response, bool, error) {
	if !strings.EqualFold(req.URL.Host, "chatgpt.com") && !strings.EqualFold(req.Host, "chatgpt.com") {
		return nil, false, nil
	}
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/backend-api/wham/agent-identities/jwks":
		body, err := CodexJWKSResponse()
		if err != nil {
			return nil, false, err
		}
		return jsonResp(req, http.StatusOK, body), true, nil
	case req.Method == http.MethodPost && strings.HasPrefix(req.URL.Path, "/backend-api/wham/v1/agent/") &&
		strings.HasSuffix(req.URL.Path, "/task/register"):
		return jsonResp(req, http.StatusOK, []byte(`{"task_id":"clawpatrol-task"}`)), true, nil
	}
	return nil, false, nil
}

// jsonResp builds an http.Response the gateway can write back to the
// agent. We bypass http.Transport entirely for synthetic responses
// — the response is constructed in-memory and flushed by the caller
// via http.Response.Write.
func jsonResp(req *http.Request, status int, body []byte) *http.Response {
	resp := &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Cache-Control", "no-store")
	return resp
}

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
	var _ runtime.HTTPCredentialResponder = (*OpenAICodexOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "openai_codex_oauth",
		New:     newer[OpenAICodexOAuth](),
		Runtime: (*OpenAICodexOAuth)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
