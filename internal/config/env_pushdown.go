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

// EnvPushdownProvider is the legacy interface credential / endpoint
// plugins implemented when they had a hardcoded env contribution. It
// is being retired: env pushdown is moving to first-class
// `environment "<type>" "<name>"` blocks (see KindEnvironment), and
// `clawpatrol env` now reads from a profile's `environments = [...]`
// list. The interface is kept here only until every built-in plugin
// has been migrated.
//
// Deprecated: implement EnvironmentRuntime on a KindEnvironment
// plugin's built body instead.
type EnvPushdownProvider interface {
	EnvVars() []EnvVar
}

// EnvironmentRuntime is what an environment plugin's built body
// implements to contribute env vars to the agent process the
// operator runs through `clawpatrol env`. One call returns the
// plugin's full contribution; the framework de-duplicates by Name
// across all the environments in a profile (first writer wins, to
// match the existing credential→endpoint precedence).
//
// EnvVars is called on every `clawpatrol env` invocation, not just
// once at boot, so plugins that need a fresh token per call (e.g.
// codex's RS256-signed Agent Identity JWT) can re-mint here. Most
// implementations return a fixed slice built at compile time from
// resolved framework refs (endpoint / credential entities).
type EnvironmentRuntime interface {
	EnvVars() []EnvVar
}
