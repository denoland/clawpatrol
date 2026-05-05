package credentials

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config/runtime"
)

// TestCodexInjectOverridesAgentAssertion confirms the auth swap path:
// codex in Agent Identity mode sends `Authorization: AgentAssertion …`
// signed with the per-task ed25519 key from the synthetic JWT the
// openai_codex_https endpoint pushes down. The MITM must overwrite
// that with `Bearer <real subscription token>` plus the real
// account-id from the bearer's JWT claims, so chatgpt.com sees a
// request indistinguishable from native ChatGPT auth. Without this
// swap, the upstream rejects with 403 "Unknown agent runtime for
// AgentAssertion" (verified live against funk).
func TestCodexInjectOverridesAgentAssertion(t *testing.T) {
	plugin := &OpenAICodexOAuth{}

	// A real-shaped chatgpt access_token JWT carrying chatgpt_account_id
	// in the auth namespace claim — same form as
	// ~/.codex/auth.json's tokens.access_token.
	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claimsJSON, _ := json.Marshal(map[string]any{
		"https://api.openai.com/auth": map[string]string{
			"chatgpt_account_id": "real-acct-7b415a8c",
		},
	})
	bearer := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))

	req, err := http.NewRequest("POST", "https://chatgpt.com/backend-api/codex/responses", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	// What codex (Agent Identity mode) would have sent on the wire.
	req.Header.Set("Authorization", "AgentAssertion eyJhZ2VudF9ydW50aW1lX2lkIjoiY2xhd3BhdHJvbC1jb2RleCIsInNpZ25hdHVyZSI6Im9wYXF1ZSJ9")
	req.Header.Set("Chatgpt-Account-Id", "clawpatrol")

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte(bearer)}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+bearer {
		t.Errorf("Authorization not swapped to bearer: got %q", got)
	}
	if got := req.Header.Get("Chatgpt-Account-Id"); got != "real-acct-7b415a8c" {
		t.Errorf("Chatgpt-Account-Id not overwritten with bearer claim: got %q", got)
	}
}
