package main

import (
	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/runtime"
)

// gatewaySecretStore is the SecretStore the gateway hands to
// credential plugins. It tries the OAuthRegistry first (so OAuth-flow
// credentials get a fresh, refreshed access token) and falls back to
// the env-var store (CLAWPATROL_SECRET_<NAME>) for static credentials
// that don't go through OAuth.
//
// The registry is keyed by credential bare-name — e.g.
// "anthropic-avocet-sub" — registered at policy load time via
// registerOAuthCredentials below, so dashboard connect / revoke
// flows operate against the same name space the policy uses.
type gatewaySecretStore struct {
	oauth *OAuthRegistry
	env   runtime.SecretStore
}

func newGatewaySecretStore(oauth *OAuthRegistry) runtime.SecretStore {
	return &gatewaySecretStore{oauth: oauth, env: runtime.EnvSecretStore{}}
}

func (s *gatewaySecretStore) Get(name, owner string) (runtime.Secret, error) {
	if s.oauth != nil {
		if tok, err := s.oauth.Token(name, owner); err != nil {
			return runtime.Secret{}, err
		} else if tok != "" {
			return runtime.Secret{Kind: "oauth_bearer", Bytes: []byte(tok)}, nil
		}
	}
	return s.env.Get(name, owner)
}

// oauthCredentialTypes maps the v14 credential type → built-in OAuth
// flow definition (auth URL / token URL / scopes / etc.). Credentials
// of these types get registered with OAuthRegistry under their bare
// name so the dashboard's connect / revoke / device-flow handlers
// see them.
var oauthCredentialTypes = map[string]string{
	// Anthropic OAuth subscription reuses the existing "claude"
	// integration default — same client_id, scopes, and refresh
	// behaviour the legacy claude integration had.
	"anthropic_oauth_subscription": "claude",
	"openai_codex_oauth":           "codex",
	// notion_oauth and the remaining OAuth-shaped credentials don't
	// have a built-in default yet. Operators set CLAWPATROL_SECRET_<NAME>
	// for now; a follow-up adds notion / slack / etc. defaults.
}

// registerOAuthCredentials walks the loaded policy and registers each
// OAuth-type credential with the OAuthRegistry under its bare name.
// Idempotent — safe to call on every config reload.
func registerOAuthCredentials(reg *OAuthRegistry, policy *config.CompiledPolicy) {
	if reg == nil || policy == nil {
		return
	}
	for name, ent := range policy.Credentials {
		defaultID, ok := oauthCredentialTypes[ent.Plugin.Type]
		if !ok {
			continue
		}
		def := defaultOAuthByID(defaultID)
		if def == nil {
			continue
		}
		// Copy by value so the registered definition's ID matches the
		// credential's bare name (the registry keys by ID).
		copy := *def
		copy.ID = name
		reg.Register(name, copy)
	}
}
