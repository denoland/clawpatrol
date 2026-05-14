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

// CardSubtitleProvider is the optional interface a credential plugin's
// decoded body implements when its non-secret HCL fields carry an
// account-level identity (Postgres / Clickhouse user, etc.) worth
// surfacing as the dashboard card subtitle. Returning "" means "no
// useful identity on the body" — the card then either shows the
// OAuth display_name (for OAuth-flow credentials post-connect) or no
// subtitle at all, rather than a misleading "Saved" placeholder.
//
// Called once per /api/state build, so implementations should be
// pure (read body fields, return a short string).
type CardSubtitleProvider interface {
	CardSubtitle() string
}
