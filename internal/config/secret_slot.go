package config

// SecretSlot describes one input the operator must fill in the
// dashboard's connect-credential modal. Single-slot credentials
// (bearer / header / cookie / api-key) declare one slot with empty
// Name; multi-slot credentials (mtls cert+key+ca, slack bot+app)
// declare one entry per named field.
//
// At runtime the secret store packs slot values into runtime.Secret:
// the unnamed slot fills Bytes; named slots fill Extras[Name].
type SecretSlot struct {
	Name        string `json:"name"`        // "" for single-slot; field name for multi
	Label       string `json:"label"`       // human label rendered in the modal
	Multiline   bool   `json:"multiline"`   // true for PEM blobs (textarea, not password input)
	Description string `json:"description"` // optional one-liner under the input
}

// SecretSlotsProvider is the optional interface a credential plugin's
// decoded body implements when the operator can connect it via the
// dashboard. OAuth-flow credentials (which use OAuthFlowProvider
// instead) leave this unimplemented; the dashboard then renders the
// OAuth connect button rather than a paste-secret modal.
//
// Plugin authors return a constant slice — slot definitions don't
// vary per credential instance.
type SecretSlotsProvider interface {
	SecretSlots() []SecretSlot
}

// NonInjectingCredential is the optional marker a credential plugin's
// decoded body implements to declare it injects nothing at request
// time — the `passthrough` type. Such a credential exists only to
// give the operator a handle that profiles can claim and bind to
// endpoints, so the existing credential→endpoint→profile claim path
// works for endpoints that simply don't need auth injection.
//
// The request-time injection path already skips these for free: their
// body satisfies none of the runtime injection interfaces
// (HTTPCredentialRuntime / HTTPRequestSigner / WebSocketCredentialRuntime
// / PostgresCredentialRuntime / …), so the gateway forwards the request
// verbatim. This marker exists purely so the dashboard can surface a
// "no injection" indicator without importing the plugin package.
type NonInjectingCredential interface {
	IsPassthrough() bool
}
