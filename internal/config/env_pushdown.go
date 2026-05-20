package config

// EnvVar is one shell variable `clawpatrol env` exports for the
// operator to source into their agent CLI's process environment.
// The Value is typically a placeholder that LOOKS like a real token
// (so the agent CLI's startup validation passes) — the gateway
// swaps in the real secret at MITM time via the bound credential
// plugin's InjectHTTP.
type EnvVar struct {
	Name        string
	Value       string
	Description string // shown as a `# comment` line above the export
}

// EnvironmentRuntime is what an environment plugin's built body
// implements to contribute env vars to the agent process the
// operator runs through `clawpatrol env`. One call returns the
// plugin's full contribution; the framework de-duplicates by Name
// across all the environments in a profile (first writer wins,
// matching the HCL-declaration order on the profile).
//
// EnvVars is called on every `clawpatrol env` invocation, not just
// once at boot, so plugins that need a fresh token per call (e.g.
// codex's RS256-signed Agent Identity JWT) can re-mint here. Most
// implementations return a fixed slice built at compile time from
// resolved framework refs (endpoint / credential entities).
type EnvironmentRuntime interface {
	EnvVars() []EnvVar
}
