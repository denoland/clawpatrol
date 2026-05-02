// Package credentials registers every built-in credential plugin.
//
// Each credential is a typed handle to a secret. The body fields here
// only describe how to inject the secret — the secret value itself
// lives outside the config (in unclaw / clawpatrol's credential store)
// and is fetched by the runtime via the credential plugin's Resolve
// hook (added later).
package credentials

import (
	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol-go/config"
)

// Bearer / cookie / header tokens — generic HTTP auth shapes ----------

// BearerToken: Authorization: Bearer <secret>. The optional
// idempotency_key flag tells the runtime to also stamp an
// Idempotency-Key header on writes, matching unclaw's apikey plugin
// behaviour for stripe-live-key.
type BearerToken struct {
	IdempotencyKey bool `hcl:"idempotency_key,optional"`
}

type CookieToken struct {
	CookieName string `hcl:"cookie_name,optional"`
}

type HeaderToken struct {
	Header string `hcl:"header"`
	Prefix string `hcl:"prefix,optional"`
}

type MTLSCredential struct{}

// PostgresCredential: the wire-protocol user the runtime uses when
// swapping the agent's StartupMessage. Password is fetched by name
// from the secret store at request time.
type PostgresCredential struct {
	User string `hcl:"user,optional"`
}

// Anthropic — manual key (X-API-Key bearer-style) and the OAuth
// subscription flow. Both bodies are empty; the credential's NAME is
// the lookup key into clawpatrol's existing oauth.go store.
type AnthropicManualKey struct{}
type AnthropicOAuthSubscription struct{}

// Slack bundles bot + app tokens for one workspace. Empty body — the
// slack plugin's runtime decides which token to inject for which API
// based on the request shape.
type SlackTokens struct{}

type TelegramBotToken struct{}
type GeminiAPIKey struct{}
type OpenAICodexOAuth struct{}
type NotionOAuth struct{}

type ClickhouseCredential struct {
	User string `hcl:"user,optional"`
}

// AWSEKSCredential: the kubernetes plugin runs `aws eks get-token` at
// request time using these parameters and uses the resulting bearer
// as the Authorization header.
type AWSEKSCredential struct {
	Cluster string `hcl:"cluster"`
	Region  string `hcl:"region"`
	Profile string `hcl:"profile,optional"`
}

func init() {
	register := func(typ string, body func() any) {
		config.Register(&config.Plugin{
			Kind: config.KindCredential,
			Type: typ,
			New:  body,
			Build: func(decoded any, name string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
				return decoded, nil
			},
		})
	}
	register("bearer_token", func() any { return &BearerToken{} })
	register("cookie_token", func() any { return &CookieToken{} })
	register("header_token", func() any { return &HeaderToken{} })
	register("mtls_credential", func() any { return &MTLSCredential{} })
	register("postgres_credential", func() any { return &PostgresCredential{} })
	register("anthropic_manual_key", func() any { return &AnthropicManualKey{} })
	register("anthropic_oauth_subscription", func() any { return &AnthropicOAuthSubscription{} })
	register("slack_tokens", func() any { return &SlackTokens{} })
	register("telegram_bot_token", func() any { return &TelegramBotToken{} })
	register("gemini_api_key", func() any { return &GeminiAPIKey{} })
	register("openai_codex_oauth", func() any { return &OpenAICodexOAuth{} })
	register("notion_oauth", func() any { return &NotionOAuth{} })
	register("clickhouse_credential", func() any { return &ClickhouseCredential{} })
	register("aws_eks_credential", func() any { return &AWSEKSCredential{} })
}
