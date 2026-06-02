package credentials

// passthrough credential plugin.
//
// Implementation notes (not part of the generated HCL reference — the
// docgen tool renders the Passthrough type doc below, so keep that one
// reader-facing and keep the mechanics here):
//
//   - No Runtime. The body satisfies none of the request-time
//     injection interfaces (HTTPCredentialRuntime / HTTPRequestSigner /
//     WebSocketCredentialRuntime / PostgresCredentialRuntime / …), so
//     the gateway's injection block (cmd/clawpatrol/main.go) skips it
//     verbatim — no header, no SQL prepend, no WS rewrite — while the
//     profile's policy rules still run on the request.
//   - Empty struct body. gohcl rejects any attribute at decode time,
//     so the bead's "carries no auth-bearing fields" rule is automatic;
//     no per-plugin Validate is needed.
//   - The `passthrough` Build hook used below is the generic
//     no-derived-state helper from util.go. The name overlap with this
//     plugin's type is cosmetic and harmless.

import (
	"github.com/denoland/clawpatrol/internal/config"
)

// Passthrough is a credential that injects nothing. It exists only as
// a handle the operator declares, binds to endpoints, and lists in a
// profile's `credentials` — so the existing credential→endpoint→profile
// claim path works for endpoints that simply don't need auth injection
// (public APIs, services reached over an already-authenticated tunnel,
// open-internal endpoints). Write one passthrough credential per group
// of credential-less endpoints a profile should claim, or share one
// across several. The gateway forwards matching requests verbatim — no
// header, signature, or token rewrite — while the profile's rules
// still apply.
type Passthrough struct{}

// IsPassthrough satisfies config.NonInjectingCredential so the
// dashboard can render a "no injection" indicator without importing
// this package.
func (*Passthrough) IsPassthrough() bool { return true }

func init() {
	var _ config.NonInjectingCredential = (*Passthrough)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "passthrough",
		New:     newer[Passthrough](),
		Runtime: nil,         // schema-only: nothing is injected at request time
		Build:   passthrough, // generic no-derived-state Build hook (util.go)
		Emit:    emptyEmit,   // empty body → no HCL attributes to serialize
	})
}
