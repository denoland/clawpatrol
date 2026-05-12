package credentials

// 1password: secret material lives in 1Password and is fetched at
// request time via the `op` CLI. The operator stores keys in a vault
// once; clawpatrol reads them on demand and stamps them onto outgoing
// requests. Cache TTL bounds how often the CLI is invoked — default
// 60s, configurable per credential.
//
// Default injection shape is `Authorization: Bearer <value>` (the
// common AI-provider API-key shape). Operators that need a different
// header / prefix override `header` and `prefix` — same knobs as
// header_token.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// defaultOnePasswordTTL bounds how often the gateway shells out to
// `op read` for the same ref. Short enough that a freshly-rotated
// secret is visible within a minute; long enough that an agent
// hammering an endpoint doesn't fork a CLI per request.
const defaultOnePasswordTTL = 60 * time.Second

// OnePassword is part of the clawpatrol plugin API.
//
// HCL:
//
//	credential "1password" "openai-prod" {
//	  ref    = "op://Engineering/OpenAI/api_key"
//	  ttl    = "60s"           // optional; default 60s
//	  header = "Authorization" // optional; default Authorization
//	  prefix = "Bearer "       // optional; default "Bearer "
//	}
//
// The `op` CLI must be installed on the gateway host and signed in
// (`op signin`) ahead of time. Fetch errors fail closed — the
// dispatcher returns 502 rather than forwarding an un-credentialed
// request.
type OnePassword struct {
	// Ref is the 1Password secret reference. Required; must start
	// with `op://`, e.g. `op://Engineering/OpenAI/api_key`.
	Ref string `hcl:"ref"`
	// TTL is the per-process cache lifetime, parsed via
	// time.ParseDuration. Default 60s. Bounds how often the gateway
	// shells out to `op` for the same ref.
	TTL string `hcl:"ttl,optional"`
	// Header is the request header to stamp. Default `Authorization`.
	Header string `hcl:"header,optional"`
	// Prefix is the string prepended to the secret value before
	// stamping. Default `Bearer ` when `header` is left at its
	// default; empty when `header` is overridden. Set to "" explicitly
	// to stamp the secret value verbatim on a custom header (e.g.
	// `X-API-Key`).
	Prefix *string `hcl:"prefix,optional"`

	// parsedTTL is populated by Build from TTL; falls back to
	// defaultOnePasswordTTL when zero.
	parsedTTL time.Duration

	// cache is the per-credential TTL cache. Sharing across plugin
	// instances would create one cache for all 1password credentials —
	// fine semantically, but a per-instance cache makes tests
	// deterministic (no leakage between subtests).
	cache opSecretCache
}

func (o *OnePassword) effectiveTTL() time.Duration {
	if o.parsedTTL > 0 {
		return o.parsedTTL
	}
	return defaultOnePasswordTTL
}

func (o *OnePassword) effectiveHeader() string {
	if o.Header != "" {
		return o.Header
	}
	return "Authorization"
}

func (o *OnePassword) effectivePrefix() string {
	// Explicit prefix wins (including the empty string, which lets
	// `X-API-Key: <value>` style headers stamp the value verbatim).
	if o.Prefix != nil {
		return *o.Prefix
	}
	// No explicit prefix + no custom header → standard bearer shape.
	if o.Header == "" {
		return "Bearer "
	}
	// Custom header, no explicit prefix → stamp verbatim.
	return ""
}

// FetchSecret implements runtime.SecretSourceProvider. The gateway's
// SecretStore calls this before falling back to env vars, so the
// returned Secret.Bytes become the value handed to InjectHTTP.
//
// Cached per-ref with TTL. Errors propagate unchanged — the dispatcher
// converts a fetch error into a 502 deny.
func (o *OnePassword) FetchSecret(ctx context.Context) (runtime.Secret, error) {
	if o.Ref == "" {
		return runtime.Secret{}, errors.New("1password credential: ref not set")
	}
	val, err := o.cache.fetch(ctx, o.Ref, o.effectiveTTL())
	if err != nil {
		return runtime.Secret{}, fmt.Errorf("1password: read %s: %w", o.Ref, err)
	}
	return runtime.Secret{Kind: "1password", Bytes: []byte(val)}, nil
}

// InjectHTTP is part of the clawpatrol plugin API.
func (o *OnePassword) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		// FetchSecret above is what populates sec.Bytes; an empty
		// value at this point means the dispatcher took a different
		// path (dashboard-paste override that came back empty, etc.).
		// Fail closed.
		return errors.New("1password: empty secret value")
	}
	req.Header.Set(o.effectiveHeader(), o.effectivePrefix()+string(sec.Bytes))
	return nil
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*OnePassword)(nil)
	var _ runtime.SecretSourceProvider = (*OnePassword)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "1password",
		New:     newer[OnePassword](),
		Runtime: (*OnePassword)(nil),
		Build:   buildOnePassword,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*OnePassword)
			b.SetAttributeValue("ref", cty.StringVal(v.Ref))
			if v.TTL != "" {
				b.SetAttributeValue("ttl", cty.StringVal(v.TTL))
			}
			if v.Header != "" {
				b.SetAttributeValue("header", cty.StringVal(v.Header))
			}
			if v.Prefix != nil {
				b.SetAttributeValue("prefix", cty.StringVal(*v.Prefix))
			}
		},
	})
}

func buildOnePassword(decoded any, name string, ctx *config.BuildCtx) (any, hcl.Diagnostics) {
	v := decoded.(*OnePassword)
	var diags hcl.Diagnostics
	if !strings.HasPrefix(v.Ref, "op://") {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "invalid 1Password secret reference",
			Detail: fmt.Sprintf(
				"credential %q: ref must start with op:// (got %q). Example: op://Engineering/OpenAI/api_key",
				name, v.Ref,
			),
			Subject: ctx.Block.DefRange.Ptr(),
		})
	}
	if v.TTL != "" {
		d, err := time.ParseDuration(v.TTL)
		if err != nil || d < 0 {
			detail := fmt.Sprintf("credential %q: ttl %q: must be a non-negative Go duration (e.g. 30s, 5m)", name, v.TTL)
			if err != nil {
				detail = fmt.Sprintf("credential %q: ttl %q: %v", name, v.TTL, err)
			}
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "invalid 1Password ttl",
				Detail:   detail,
				Subject:  ctx.Block.DefRange.Ptr(),
			})
		} else {
			v.parsedTTL = d
		}
	}
	return v, diags
}

// ---- exec / cache plumbing -------------------------------------------------

// opReader is the package-level fetch entrypoint. Tests overwrite it
// with a fake that returns canned bytes; production points it at
// `op read`.
var opReader = realOpRead

// realOpRead shells out to the 1Password CLI. Returns the secret value
// with any trailing newline stripped. Stderr is folded into the error
// message so misconfigured signins surface clearly in the gateway log.
func realOpRead(ctx context.Context, ref string) (string, error) {
	cmd := exec.CommandContext(ctx, "op", "read", "--no-newline", ref)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr := strings.TrimSpace(string(ee.Stderr))
			if stderr == "" {
				return "", fmt.Errorf("op read: exit %d", ee.ExitCode())
			}
			return "", fmt.Errorf("op read: exit %d: %s", ee.ExitCode(), stderr)
		}
		// exec.LookPath / fork failure (op not installed at all).
		return "", fmt.Errorf("op read: %w", err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// opSecretCache holds one ref→value entry with an expiry. Per-instance
// (not package-global) so policy reloads / tests don't leak cache
// state across runs.
type opSecretCache struct {
	mu      sync.Mutex
	entries map[string]opCacheEntry
}

type opCacheEntry struct {
	value   string
	expires time.Time
}

func (c *opSecretCache) fetch(ctx context.Context, ref string, ttl time.Duration) (string, error) {
	now := time.Now()
	c.mu.Lock()
	if c.entries != nil {
		if e, ok := c.entries[ref]; ok && now.Before(e.expires) {
			c.mu.Unlock()
			return e.value, nil
		}
	}
	c.mu.Unlock()
	val, err := opReader(ctx, ref)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]opCacheEntry{}
	}
	c.entries[ref] = opCacheEntry{value: val, expires: now.Add(ttl)}
	c.mu.Unlock()
	return val, nil
}
