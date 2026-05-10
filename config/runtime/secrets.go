package runtime

import (
	"fmt"
	"os"
	"strings"
)

// envParts lists the recognized "multi-part" suffixes EnvSecretStore
// folds into Secret.Extras when the bare CLAWPATROL_SECRET_<NAME> var
// is empty. Plugins like mtls_credential need three pieces (cert /
// key / ca); the env-var convention is one var per piece.
var envParts = []string{"CA", "CERT", "KEY"}

// SecretStore returns the secret material a credential plugin's
// InjectHTTP / InjectPostgres needs at request time. Lookups are
// keyed by the credential's bare name (e.g. "github-pat") plus the
// owner — typically the agent's tailnet identity, so the same
// credential type can hold per-user secrets.
//
// Implementations live outside the config package because the secret
// store is a host concern, not a policy concern. The default env-var
// store is lightweight enough for development; a follow-up wires the
// existing OAuthRegistry behind this interface for OAuth-flow
// credentials (anthropic / codex / notion / etc.) so refresh + per-
// owner persistence flow through the same path.
type SecretStore interface {
	Get(name, owner string) (Secret, error)
}

// EnvSecretStore reads secret material from process env vars. Lookup
// key: CLAWPATROL_SECRET_<UPPER_NAME> with hyphens normalized to
// underscores. Returns an empty Secret (no error) when the var
// isn't set so the dispatcher can decide between fail-closed and
// passthrough at the policy level.
//
// Owner is ignored — env-var-backed stores are single-tenant. A
// per-owner extension would key on `_<OWNER>` suffix.
type EnvSecretStore struct{}

// Get is part of the clawpatrol plugin API.
func (EnvSecretStore) Get(name, _ string) (Secret, error) {
	if name == "" {
		return Secret{}, fmt.Errorf("empty credential name")
	}
	base := "CLAWPATROL_SECRET_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	sec := Secret{}
	if v, err := readEnvSecret(base); err != nil {
		return Secret{}, err
	} else if v != "" {
		sec.Bytes = []byte(v)
	}
	for _, part := range envParts {
		v, err := readEnvSecret(base + "_" + part)
		if err != nil {
			return Secret{}, err
		}
		if v == "" {
			continue
		}
		if sec.Extras == nil {
			sec.Extras = make(map[string]string, len(envParts))
		}
		sec.Extras[strings.ToLower(part)] = v
	}
	return sec, nil
}

// readEnvSecret reads CLAWPATROL_SECRET_<...>. Values starting with
// "@" are treated as file paths (the rest is read off disk) — keeps
// PEM bundles out of the env table while still letting operators
// declare the binding via env vars. Empty + missing return "".
func readEnvSecret(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", nil
	}
	if strings.HasPrefix(v, "@") {
		data, err := os.ReadFile(v[1:])
		if err != nil {
			return "", fmt.Errorf("%s=@%s: %w", key, v[1:], err)
		}
		return string(data), nil
	}
	return v, nil
}
