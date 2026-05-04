package credentials

// Shared helpers for the per-provider credential plugins. Each
// provider lives in its own file (slack.go, postgres.go, …) and
// registers itself via init(); this file holds the cross-cutting
// boilerplate that didn't earn a home of its own.

import (
	"net/http"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
)

// emptyEmit is the no-op Emit used by credentials whose body has no
// HCL attributes (most empty-struct credentials).
func emptyEmit(_ any, _ string, _ *hclwrite.Body) {}

// newer returns a New() func that allocates a fresh *T. Cheaper than
// repeating `func() any { return &Foo{} }` in each plugin's init.
func newer[T any]() func() any { return func() any { return new(T) } }

// passthrough is the Build hook every credential uses — credentials
// own no derived state beyond their decoded body.
func passthrough(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return decoded, nil
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
	for _, p := range strings.Split(cur, ",") {
		if strings.TrimSpace(p) == beta {
			return
		}
	}
	h.Set("anthropic-beta", cur+","+beta)
}

// Per-provider env-var placeholders. Chosen to look like real tokens
// so the agent CLI's startup validation accepts them; the gateway
// overwrites the slot at MITM time so the placeholder bytes never
// reach the upstream.
const (
	phClaude = "sk-ant-oat01-clawpatrol-placeholder-do-not-use"
	phOpenAI = "sk-clawpatrol-placeholder-do-not-use"
	phGitHub = "ghp_clawpatrol_placeholder_do_not_use"
	phGemini = "AIzaClawpatrolPlaceholderDoNotUse00000000"
)
