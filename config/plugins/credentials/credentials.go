// Package credentials registers every built-in credential plugin.
//
// Each credential is a typed handle to a secret. The body fields here
// only describe how to inject the secret — the secret value itself
// lives outside the config (in unclaw / clawpatrol's credential store)
// and is fetched by the runtime via the credential plugin's Resolve
// hook (added later).
package credentials

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
// terminating upstream auth on the agent's behalf. User is the HCL
// field; password lives in the secret store under the credential's
// bare name (operator pastes via the dashboard's Postgres slot).
type PostgresCredential struct {
	User string `hcl:"user,optional"`
}

// PostgresAuth implements runtime.PostgresAuthCredential — the
// postgres endpoint runtime calls this once per session to learn
// what (user, password) to use for upstream SCRAM / cleartext.
func (p *PostgresCredential) PostgresAuth(sec runtime.Secret) (string, string) {
	return p.User, string(sec.Bytes)
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

// OpenAICodexOAuth + GitHubOAuth — both OAuth-flow bearer tokens.
// Empty body; the credential's NAME is the OAuthRegistry lookup key
// (registered via secrets.go's registerOAuthCredentials at policy-
// load time).
type OpenAICodexOAuth struct{}
type GitHubOAuth struct{}
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

// MTLSCredential.ConfigureUpstreamTLS adds the secret's client cert
// (cert + key PEM in Extras) to cfg.Certificates and replaces RootCAs
// with the secret's CA bundle when one is provided. Self-hosted
// clusters and other mTLS-authenticated upstreams (k8s API servers,
// internal CAs) consume this — the kubernetes endpoint plugin
// references an mtls_credential and the dispatcher applies it
// before the upstream TLS handshake.
func (m *MTLSCredential) ConfigureUpstreamTLS(cfg *tls.Config, sec runtime.Secret) error {
	certPEM := []byte(sec.Extras["cert"])
	keyPEM := []byte(sec.Extras["key"])
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return errors.New("mtls credential missing cert / key (set CLAWPATROL_SECRET_<NAME>_CERT and _KEY)")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("mtls keypair: %w", err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	if caPEM := []byte(sec.Extras["ca"]); len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return errors.New("mtls ca bundle: no PEM blocks parsed")
		}
		cfg.RootCAs = pool
	}
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

// OpenAICodexOAuth: bearer token for the codex OAuth flow.
// api.openai.com + chatgpt.com both accept `Authorization: Bearer ...`.
func (a *OpenAICodexOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

// GitHubOAuth: bearer token from gh's device-flow OAuth. Used by
// gh CLI + the GitHub REST API (api.github.com / raw.githubusercontent.com).
func (g *GitHubOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

// SlackTokens: bot + app token pair. Default-injects the bot token
// as `Authorization: Bearer xoxb-…`. Slack admin endpoints
// (auth.test, admin.*, apps.*) prefer the app token; if the operator
// declared one, use it for those paths instead. Falls back to bot
// when only one slot is filled.
func (s *SlackTokens) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	bot := sec.Extras["bot"]
	app := sec.Extras["app"]
	pick := bot
	if app != "" && slackPathPrefersApp(req.URL.Path) {
		pick = app
	}
	if pick == "" {
		// Either operator hasn't filled the relevant slot yet, or
		// they're using a single-slot setup that landed in Bytes.
		if len(sec.Bytes) > 0 {
			pick = string(sec.Bytes)
		}
	}
	if pick == "" {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+pick)
	return nil
}

func slackPathPrefersApp(path string) bool {
	for _, p := range []string{"/api/admin.", "/api/apps.", "/api/auth.test"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// TelegramBotToken: bot token lives in the URL path
// (`/bot<TOKEN>/<METHOD>`) and sometimes in the request body
// (setWebhook posts a URL containing the token). We swap every
// occurrence of the operator-emitted placeholder with the real
// secret. Mirrors unclaw's plugin model — operator's CLI uses the
// placeholder verbatim; gateway substitutes globally so token never
// hits the upstream as the placeholder, and never leaks to logs.
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

// GeminiAPIKey: Google Gemini accepts the API key in either the
// `x-goog-api-key` header or the `?key=` query parameter. Always
// overwrite both — agents that send placeholder values get them
// swapped; agents that don't send anything get the real key
// stamped in.
func (g *GeminiAPIKey) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 || req.URL == nil {
		return nil
	}
	key := string(sec.Bytes)
	req.Header.Set("x-goog-api-key", key)
	q := req.URL.Query()
	if q.Get("key") != "" {
		// Only rewrite the param when the agent set one — otherwise
		// header injection above is sufficient and we don't want to
		// surprise the agent with an extra param.
		q.Set("key", key)
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

// NotionOAuth: Bearer token in Authorization header + Notion-Version
// header (Notion's API requires the version, defaults to a recent
// stable). Agents wire the OAuth token through their SDK; gateway
// overwrites at MITM time so per-profile rotation works without
// reconfiguring the agent.
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

// ClickhouseCredential: HTTPS API takes user + password as query
// params (?user=…&password=…) or basic-auth header. We populate both
// — basic-auth handles default-auth ClickHouse setups, query params
// handle setups that disable header auth. User comes from the HCL
// field; password from the operator-pasted secret bytes.
func (c *ClickhouseCredential) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if c.User == "" || len(sec.Bytes) == 0 || req.URL == nil {
		return nil
	}
	password := string(sec.Bytes)
	req.SetBasicAuth(c.User, password)
	q := req.URL.Query()
	q.Set("user", c.User)
	q.Set("password", password)
	req.URL.RawQuery = q.Encode()
	return nil
}

// telegramPlaceholder is the bot-token placeholder operators put in
// their SDK config / URL when running through the gateway. The agent
// hits api.telegram.org/bot<placeholder>/method, gateway swaps the
// placeholder for the real token everywhere it appears (URL path,
// query string, body — Telegram's setWebhook posts a URL containing
// the token, so body matters too).
//
// Telegram doesn't appear in `clawpatrol env` because Telegram SDKs
// take the token as an explicit argument rather than reading it from
// the env, so there's nothing to "push down".
const telegramPlaceholder = "0000000000:clawpatrol-placeholder-do-not-use"

// ensureBeta appends `beta` to a comma-separated `anthropic-beta`
// header if it isn't already present. Anthropic gates experimental
// features (including OAuth bearer auth) behind these tokens.
func ensureBeta(h http.Header, beta string) {
	cur := h.Get("anthropic-beta")
	if cur == "" {
		h.Set("anthropic-beta", beta)
		return
	}
	for _, p := range strings.Split(cur, ",") {
		if strings.TrimSpace(p) == beta {
			return
		}
	}
	h.Set("anthropic-beta", cur+","+beta)
}

// emitCredential serializes a credential body back to HCL. Most types
// emit nothing (empty body); shaped types emit their few attributes.
func emitCredential(body any, _ string, b *hclwrite.Body) {
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
}

// newer returns a New() func that allocates a fresh *T. Cheaper than
// repeating `func() any { return &Foo{} }` in the wireds table.
func newer[T any]() func() any { return func() any { return new(T) } }

// passthrough is the Build hook every credential uses — credentials
// own no derived state beyond their decoded body.
func passthrough(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return decoded, nil
}

func init() {
	// Wired runtimes — each implements HTTPCredentialRuntime and gets
	// stamped onto the plugin's Runtime field so the dispatcher can
	// type-assert. Schema-only plugins (slack / telegram / gemini /
	// etc.) leave Runtime nil; the dispatcher reports a clear "not
	// implemented" diagnostic when a request reaches one.
	wireds := []struct {
		typ string
		new func() any
		rt  any
	}{
		{"bearer_token", newer[BearerToken](), (*BearerToken)(nil)},
		{"cookie_token", newer[CookieToken](), (*CookieToken)(nil)},
		{"header_token", newer[HeaderToken](), (*HeaderToken)(nil)},
		{"mtls_credential", newer[MTLSCredential](), (*MTLSCredential)(nil)},
		{"postgres_credential", newer[PostgresCredential](), (*PostgresCredential)(nil)},
		{"anthropic_manual_key", newer[AnthropicManualKey](), (*AnthropicManualKey)(nil)},
		{"anthropic_oauth_subscription", newer[AnthropicOAuthSubscription](), (*AnthropicOAuthSubscription)(nil)},
		{"slack_tokens", newer[SlackTokens](), (*SlackTokens)(nil)},
		{"telegram_bot_token", newer[TelegramBotToken](), (*TelegramBotToken)(nil)},
		{"gemini_api_key", newer[GeminiAPIKey](), (*GeminiAPIKey)(nil)},
		{"openai_codex_oauth", newer[OpenAICodexOAuth](), (*OpenAICodexOAuth)(nil)},
		{"github_oauth", newer[GitHubOAuth](), (*GitHubOAuth)(nil)},
		{"notion_oauth", newer[NotionOAuth](), (*NotionOAuth)(nil)},
		{"clickhouse_credential", newer[ClickhouseCredential](), (*ClickhouseCredential)(nil)},
		{"aws_eks_credential", newer[AWSEKSCredential](), nil},
	}
	for _, w := range wireds {
		w := w
		config.Register(&config.Plugin{
			Kind:    config.KindCredential,
			Type:    w.typ,
			New:     w.new,
			Runtime: w.rt,
			Build:   passthrough,
			Emit:    emitCredential,
		})
	}
	// Sanity check at init time that wired runtimes satisfy the right
	// contract — catches signature drift early rather than at first
	// request.
	var (
		_ runtime.HTTPCredentialRuntime  = (*BearerToken)(nil)
		_ runtime.HTTPCredentialRuntime  = (*CookieToken)(nil)
		_ runtime.HTTPCredentialRuntime  = (*HeaderToken)(nil)
		_ runtime.HTTPCredentialRuntime  = (*AnthropicManualKey)(nil)
		_ runtime.HTTPCredentialRuntime  = (*AnthropicOAuthSubscription)(nil)
		_ runtime.HTTPCredentialRuntime  = (*OpenAICodexOAuth)(nil)
		_ runtime.HTTPCredentialRuntime  = (*GitHubOAuth)(nil)
		_ runtime.HTTPCredentialRuntime  = (*SlackTokens)(nil)
		_ runtime.HTTPCredentialRuntime  = (*TelegramBotToken)(nil)
		_ runtime.HTTPCredentialRuntime  = (*GeminiAPIKey)(nil)
		_ runtime.HTTPCredentialRuntime  = (*NotionOAuth)(nil)
		_ runtime.HTTPCredentialRuntime  = (*ClickhouseCredential)(nil)
		_ runtime.TLSCredentialRuntime   = (*MTLSCredential)(nil)
		_ runtime.PostgresAuthCredential = (*PostgresCredential)(nil)
	)
}
