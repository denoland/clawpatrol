package runtime

// BlobStore is the plugin-facing persistent byte store. Endpoint /
// credential plugins that need to remember opaque bytes across boots
// — SSH endpoint host keys, OAuth signing material — call into this
// instead of touching the filesystem directly.
//
// The host (clawpatrol gateway) backs it with a sqlite table; tests
// can substitute an in-memory map. Plugins address rows by
// (kind, name): kind is the plugin's stable namespace
// ("ssh_host_key", "codex_jwt_keys"), name is whatever sub-key the
// plugin needs (the endpoint name, or empty string for plugin-
// singleton blobs).
//
// Why a small typed interface rather than the SecretStore: secrets
// are credential-bound, owned-by-profile, and resolved through a
// lookup chain (dashboard / OAuth / env). Blobs are plugin-internal
// state with no owner concept — separating the contracts keeps each
// one simple and lets plugin authors pick the right one without
// stretching SecretStore semantics.
type BlobStore interface {
	Get(kind, name string) ([]byte, bool, error)
	Put(kind, name string, data []byte) error
}
