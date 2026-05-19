package config

// EnvVar is one shell variable `clawpatrol env` exports for the
// operator to source into their agent CLI's process environment.
// The Value is a placeholder that LOOKS like a real token (so the
// agent CLI's startup validation passes) — the gateway swaps in
// the real secret at MITM time via the credential plugin's
// InjectHTTP.
type EnvVar struct {
	Name        string
	Value       string
	Description string // shown as a `# comment` line above the export
}

// EnvPushdownProvider is the optional interface a credential plugin
// implements when an agent CLI expects to read its credential out of
// a process environment variable. `clawpatrol env` walks every
// registered credential plugin's EnvVars() and prints the union as
// shell `export ...` lines.
//
// Plugins that don't have a CLI integration story (mtls / generic
// bearer / generic header) leave this unimplemented; they show up
// only in the dashboard.
type EnvPushdownProvider interface {
	EnvVars() []EnvVar
}
