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

// registerOAuthCredentials walks the loaded policy and registers each
// OAuth-flow credential with the OAuthRegistry under its bare name.
// The OAuth flow data (auth/token URLs, scopes, client id) lives on
// the credential plugin itself via the OAuthFlow() method — see
// config/plugins/credentials/oauth_flows.go. Idempotent — safe to
// call on every config reload.
func registerOAuthCredentials(reg *OAuthRegistry, policy *config.CompiledPolicy) {
	if reg == nil || policy == nil {
		return
	}
	for name, ent := range policy.Credentials {
		fp, ok := ent.Body.(config.OAuthFlowProvider)
		if !ok {
			continue
		}
		flow := fp.OAuthFlow()
		if flow == nil {
			continue
		}
		copy := *flow
		copy.ID = name // registry keys by ID; bare name is the lookup key
		reg.Register(name, copy)
	}
}
