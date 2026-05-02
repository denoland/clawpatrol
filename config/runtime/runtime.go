// Package runtime hosts the request-time dispatcher and the plugin
// runtime interfaces. The architecture mirrors unclaw's plugin
// runtime: endpoint plugins own protocol decoding, credential plugins
// own secret injection, approver plugins own arbitration. Built-in
// plugins satisfy these interfaces directly; a future distribution
// layer would slot in behind the same shapes.
package runtime

import (
	"context"
	"errors"
	"net/http"

	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/match"
)

// HTTPCredentialRuntime is the credential-plugin contract for HTTP
// auth shapes (bearer / cookie / header / mtls / OAuth-with-bearer).
// Inject mutates req.Header (and maybe req.URL if cookies involve a
// path); the secret string is fetched out-of-band by the host (e.g.
// via clawpatrol's existing OAuthRegistry) and passed in as Secret.
//
// Implementations live next to their config plugin so the schema and
// runtime stay co-located, mirroring unclaw's plugin layout.
type HTTPCredentialRuntime interface {
	InjectHTTP(ctx context.Context, req *http.Request, sec Secret) error
}

// PostgresCredentialRuntime swaps the agent's StartupMessage password
// for the real one before the upstream connect. The wire-protocol
// front-end calls this once per session.
type PostgresCredentialRuntime interface {
	InjectPostgres(ctx context.Context, startup PostgresStartup, sec Secret) error
}

// Secret is what credential plugins receive at injection time. The
// Bytes are the actual secret material; Kind disambiguates what shape
// the credential expects (bearer / api-key / cookie / mTLS bundle /
// postgres password / ...). The host (clawpatrol) fetches the value
// from its existing oauth.go store before calling the plugin.
type Secret struct {
	Kind  string
	Bytes []byte
	// Extras is plugin-specific. mTLS passes cert / key / chain;
	// postgres passes user; OAuth passes refresh token + expiry.
	Extras map[string]string
}

// PostgresStartup is the view a postgres credential plugin sees of
// the StartupMessage it must rewrite. The wire-protocol front-end
// fills it; the credential plugin updates Password + optionally User.
type PostgresStartup struct {
	User     string
	Database string
	Password string
}

// ApproverRuntime evaluates one stage of an approve = [...] chain.
// LLMApprover and HumanApprover plugins both implement it; the
// outcome semantics are the same — return Verdict + reason or surface
// a timeout.
type ApproverRuntime interface {
	Approve(ctx context.Context, req ApproveRequest) (ApproveVerdict, error)
}

// ApproveRequest is the bundle handed to ApproverRuntime.Approve.
// Plugins read whatever they need (a Slack-targeted human approver
// reads only the summary; an LLM approver reads the full body).
type ApproveRequest struct {
	Stage    config.ApproveStage
	Endpoint *config.CompiledEndpoint
	Rule     *config.CompiledRule
	Request  *match.Request
	// Policy text resolved from the stage's Policy reference, when
	// the stage names one. Empty for bare-name stages.
	PolicyText string
	// Defaults from the file's defaults {} block; plugins fall back
	// to these when their own config doesn't override.
	Defaults config.Defaults
}

// ApproveVerdict is what an approver returns. "" Decision means the
// approver couldn't decide (timeout / error) — the caller falls back
// to the configured fail mode.
type ApproveVerdict struct {
	Decision string // "allow" | "deny" | ""
	Reason   string
}

// ErrUnsupported is returned by a plugin's runtime hook when the
// requested operation isn't implemented for that plugin yet (e.g.
// clickhouse_native endpoints have schema only). The dispatcher
// translates this into a clear "endpoint runtime not implemented"
// log entry and a 503 to the agent.
var ErrUnsupported = errors.New("plugin runtime not implemented")

// PlaceholderDetector is the optional contract an endpoint plugin's
// runtime implements so the multi-credential dispatch logic can ask
// it: "given this incoming request and these candidate placeholders,
// which one (if any) did the agent send?"
//
// The returned string must be one of `candidates` exactly, or "" if
// no placeholder matched (the caller then falls back to the
// no-placeholder credential entry, when one exists).
//
// Why an endpoint-plugin method rather than a callback handed to
// ResolveCredential: each protocol family hides placeholders in a
// different slot. HTTPS scans the Authorization header. Postgres
// reads the StartupMessage password. Putting the extraction logic on
// the endpoint plugin keeps the dispatcher protocol-agnostic.
//
// Endpoints with only singular `credential = X` bindings don't need
// to implement this — ResolveCredential short-circuits before
// calling it.
type PlaceholderDetector interface {
	DetectPlaceholder(req *Request, candidates []string) string
}

// Request is re-exported here so callers don't have to import
// config/match for the placeholder-detector signature.
type Request = match.Request
