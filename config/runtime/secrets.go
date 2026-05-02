package runtime

import (
	"fmt"
	"os"
	"strings"
)

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

func (EnvSecretStore) Get(name, owner string) (Secret, error) {
	if name == "" {
		return Secret{}, fmt.Errorf("empty credential name")
	}
	key := "CLAWPATROL_SECRET_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	v := os.Getenv(key)
	if v == "" {
		return Secret{}, nil
	}
	return Secret{Bytes: []byte(v)}, nil
}
