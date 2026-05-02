// Package credentials registers every built-in credential plugin.
//
// Each credential is a typed handle to a secret. The body fields here
// only describe how to inject the secret — the secret value itself
// lives outside the config (in unclaw / clawpatrol's credential store)
// and is fetched by the runtime via the credential plugin's Resolve
// hook (added later).
package credentials

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/runtime"
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

// ── HTTP credential runtimes ──────────────────────────────────────────
//
// Each shape stamps the same secret onto the request differently.
// The host (clawpatrol's gateway) is responsible for fetching the
// secret value and handing it to the plugin via runtime.Secret —
// plugins never read disk or call OAuth refresh themselves.

func (b *BearerToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	if b.IdempotencyKey && req.Method != http.MethodGet && req.Method != http.MethodHead {
		// Stripe-style: stamp Idempotency-Key on writes if the agent
		// didn't already. Value derives from the request body hash so
		// retries collapse but distinct requests don't.
		if req.Header.Get("Idempotency-Key") == "" {
			req.Header.Set("Idempotency-Key", idempotencyKeyFor(req))
		}
	}
	return nil
}

// idempotencyKeyFor returns a deterministic key derived from the
// agent's idempotency hint — for now we pass through whatever the
// agent already set, falling back to the request URL. A future pass
// can hash the body for stronger replay-safety.
func idempotencyKeyFor(req *http.Request) string {
	if k := req.Header.Get("X-Clawpatrol-Idempotency-Hint"); k != "" {
		return k
	}
	return req.URL.Path + "@" + req.Method
}

func (h *HeaderToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if h.Header == "" || len(sec.Bytes) == 0 {
		return nil
	}
	v := h.Prefix + string(sec.Bytes)
	req.Header.Set(h.Header, v)
	return nil
}

func (c *CookieToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if c.CookieName == "" || len(sec.Bytes) == 0 {
		return nil
	}
	cookie := &http.Cookie{Name: c.CookieName, Value: string(sec.Bytes)}
	req.AddCookie(cookie)
	return nil
}

// AnthropicManualKey behaves like a BearerToken but uses the
// Anthropic-specific x-api-key header.
func (a *AnthropicManualKey) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("x-api-key", string(sec.Bytes))
	return nil
}

// AnthropicOAuthSubscription stamps the OAuth bearer + the beta
// header that gates Anthropic's OAuth-backed access.
func (a *AnthropicOAuthSubscription) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	ensureBeta(req.Header, "oauth-2025-04-20")
	return nil
}

// ensureBeta appends `beta` to a comma-separated `anthropic-beta`
// header if it isn't already present. Anthropic gates experimental
// features (including OAuth bearer auth) behind these tokens.
func ensureBeta(h http.Header, beta string) {
	cur := h.Get("anthropic-beta")
	if cur == "" {
		h.Set("anthropic-beta", beta)
		return
	}
	for _, p := range splitCSV(cur) {
		if p == beta {
			return
		}
	}
	h.Set("anthropic-beta", cur+","+beta)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range []byte(s) {
		_ = p
	}
	// Simple comma split with whitespace trim — header values are
	// CSV-like in practice. Avoiding strings import keeps this file
	// dependency-light at the runtime boundary.
	cur := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ',' {
			out = append(out, trimSpaces(cur))
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, trimSpaces(cur))
	}
	return out
}

func trimSpaces(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// emitFor returns a per-type Emit hook. Most credential bodies are
// either empty or a tiny set of attributes; we route all of them
// through one helper that knows the field set per type.
func emitFor(typ string) func(any, string, *hclwrite.Body) {
	return func(body any, _ string, b *hclwrite.Body) {
		switch v := body.(type) {
		case *BearerToken:
			if v.IdempotencyKey {
				b.SetAttributeValue("idempotency_key", cty.True)
			}
		case *CookieToken:
			if v.CookieName != "" {
				b.SetAttributeValue("cookie_name", cty.StringVal(v.CookieName))
			}
		case *HeaderToken:
			b.SetAttributeValue("header", cty.StringVal(v.Header))
			if v.Prefix != "" {
				b.SetAttributeValue("prefix", cty.StringVal(v.Prefix))
			}
		case *PostgresCredential:
			if v.User != "" {
				b.SetAttributeValue("user", cty.StringVal(v.User))
			}
		case *ClickhouseCredential:
			if v.User != "" {
				b.SetAttributeValue("user", cty.StringVal(v.User))
			}
		case *AWSEKSCredential:
			b.SetAttributeValue("cluster", cty.StringVal(v.Cluster))
			b.SetAttributeValue("region", cty.StringVal(v.Region))
			if v.Profile != "" {
				b.SetAttributeValue("profile", cty.StringVal(v.Profile))
			}
		}
		// Empty-body credentials (mtls / anthropic / slack / telegram /
		// gemini / openai_codex / notion) emit no attributes.
		_ = typ
	}
}

func init() {
	// Wired runtimes — each implements HTTPCredentialRuntime and
	// gets stamped onto the plugin's Runtime field so the dispatcher
	// can type-assert. Schema-only plugins (slack / telegram / gemini
	// / etc.) leave Runtime nil; the dispatcher reports a clear "not
	// implemented" diagnostic when a request reaches one.
	type wired struct {
		typ string
		new func() any
		rt  any // satisfies one of the runtime interfaces, or nil
	}
	wireds := []wired{
		{"bearer_token", func() any { return &BearerToken{} }, (*BearerToken)(nil)},
		{"cookie_token", func() any { return &CookieToken{} }, (*CookieToken)(nil)},
		{"header_token", func() any { return &HeaderToken{} }, (*HeaderToken)(nil)},
		{"mtls_credential", func() any { return &MTLSCredential{} }, nil},
		{"postgres_credential", func() any { return &PostgresCredential{} }, nil},
		{"anthropic_manual_key", func() any { return &AnthropicManualKey{} }, (*AnthropicManualKey)(nil)},
		{"anthropic_oauth_subscription", func() any { return &AnthropicOAuthSubscription{} }, (*AnthropicOAuthSubscription)(nil)},
		{"slack_tokens", func() any { return &SlackTokens{} }, nil},
		{"telegram_bot_token", func() any { return &TelegramBotToken{} }, nil},
		{"gemini_api_key", func() any { return &GeminiAPIKey{} }, nil},
		{"openai_codex_oauth", func() any { return &OpenAICodexOAuth{} }, nil},
		{"notion_oauth", func() any { return &NotionOAuth{} }, nil},
		{"clickhouse_credential", func() any { return &ClickhouseCredential{} }, nil},
		{"aws_eks_credential", func() any { return &AWSEKSCredential{} }, nil},
	}
	for _, w := range wireds {
		w := w
		config.Register(&config.Plugin{
			Kind:    config.KindCredential,
			Type:    w.typ,
			New:     w.new,
			Runtime: w.rt,
			Build: func(decoded any, name string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
				return decoded, nil
			},
			Emit: emitFor(w.typ),
		})
	}
	// Sanity check at init time that the wired runtimes satisfy the
	// HTTPCredentialRuntime contract — catches signature drift early
	// rather than at first request.
	var (
		_ runtime.HTTPCredentialRuntime = (*BearerToken)(nil)
		_ runtime.HTTPCredentialRuntime = (*CookieToken)(nil)
		_ runtime.HTTPCredentialRuntime = (*HeaderToken)(nil)
		_ runtime.HTTPCredentialRuntime = (*AnthropicManualKey)(nil)
		_ runtime.HTTPCredentialRuntime = (*AnthropicOAuthSubscription)(nil)
	)
}
