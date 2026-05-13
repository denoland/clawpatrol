package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// gatewaySecretStore is the SecretStore the gateway hands to
// credential plugins. Lookup order per credential name:
//
//  1. credential_secrets table — slot bytes the operator pasted into
//     the dashboard (single-slot fills Bytes; multi-slot fills Extras).
//  2. OAuthRegistry — for OAuth-flow credentials (claude / codex /
//     github / ...), returns a refreshed access token.
//  3. EnvSecretStore — CLAWPATROL_SECRET_<NAME>, last-resort fallback
//     for operator-managed env-var secrets.
//
// All three keyspaces are the credential's bare name, so a credential
// declared `credential "bearer_token" "stripe-live" {}` is reachable
// via the dashboard, the OAuth registry (if it grew an OAuth flow),
// or `CLAWPATROL_SECRET_STRIPE-LIVE`, in that priority.
type gatewaySecretStore struct {
	db    *sql.DB
	oauth *OAuthRegistry
	env   runtime.SecretStore
}

func newGatewaySecretStore(db *sql.DB, oauth *OAuthRegistry) runtime.SecretStore {
	return &gatewaySecretStore{db: db, oauth: oauth, env: runtime.EnvSecretStore{}}
}

// SetCredentialSlot upserts one slot row into credential_secrets,
// satisfying tailscaleproto.SecretWriter. The tsnet ipn.StateStore
// round-trips machine key, node key, and login profile through here
// on first-time node auth and on every state mutation thereafter.
func (s *gatewaySecretStore) SetCredentialSlot(name, slot, value string) error {
	if s.db == nil {
		return fmt.Errorf("gateway secret store: no db")
	}
	return setCredentialSlot(s.db, name, slot, value)
}

func (s *gatewaySecretStore) Get(name string) (runtime.Secret, error) {
	if s.db != nil {
		sec, ok, err := readCredentialSecrets(s.db, name)
		if err != nil {
			return runtime.Secret{}, err
		}
		if ok {
			return sec, nil
		}
	}
	if s.oauth != nil {
		if tok, err := s.oauth.Token(name); err != nil {
			return runtime.Secret{}, err
		} else if tok != "" {
			return runtime.Secret{Kind: "oauth_bearer", Bytes: []byte(tok)}, nil
		}
	}
	return s.env.Get(name)
}

// readCredentialSecrets fetches every slot persisted for the named
// credential. Returns (Secret, true) when at least one slot exists.
// The unnamed slot (slot = "") fills Bytes; named slots fill Extras.
func readCredentialSecrets(db *sql.DB, credential string) (runtime.Secret, bool, error) {
	rows, err := db.Query(
		`SELECT slot, value FROM credential_secrets WHERE credential = ?`,
		credential,
	)
	if err != nil {
		return runtime.Secret{}, false, err
	}
	defer func() { _ = rows.Close() }()
	sec := runtime.Secret{Kind: "dashboard"}
	found := false
	for rows.Next() {
		var slot, value string
		if err := rows.Scan(&slot, &value); err != nil {
			return runtime.Secret{}, false, err
		}
		found = true
		if slot == "" {
			sec.Bytes = []byte(value)
			continue
		}
		if sec.Extras == nil {
			sec.Extras = map[string]string{}
		}
		sec.Extras[slot] = value
	}
	return sec, found, rows.Err()
}

// setCredentialSlot upserts one (credential, slot) row. Used by the
// dashboard's connect-credential endpoint.
func setCredentialSlot(db *sql.DB, credential, slot, value string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	_, err := db.Exec(
		`INSERT INTO credential_secrets (credential, slot, value, updated_ns)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(credential, slot) DO UPDATE SET
		   value = excluded.value, updated_ns = excluded.updated_ns`,
		credential, slot, value, time.Now().UnixNano(),
	)
	return err
}

// clearCredentialSecrets drops every slot for the named credential.
// The dashboard's disconnect button calls this.
func clearCredentialSecrets(db *sql.DB, credential string) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(
		`DELETE FROM credential_secrets WHERE credential = ?`,
		credential,
	)
	return err
}

// credentialSlotPresence returns the set of slots persisted for the
// named credential. Used by the dashboard to render per-slot
// "filled / empty" status without leaking the secret bytes.
func credentialSlotPresence(db *sql.DB, credential string) (map[string]bool, error) {
	out := map[string]bool{}
	if db == nil {
		return out, nil
	}
	rows, err := db.Query(
		`SELECT slot FROM credential_secrets WHERE credential = ?`,
		credential,
	)
	if err != nil {
		return out, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var slot string
		if err := rows.Scan(&slot); err != nil {
			return out, err
		}
		out[slot] = true
	}
	return out, rows.Err()
}

// gatewayBlobStore is the host-side BlobStore: plugins persist opaque
// bytes here keyed by (kind, name), backed by the gateway_blobs sqlite
// table. Companion to gatewaySecretStore — that one handles
// credential-scoped material, this one handles plugin-internal state.
type gatewayBlobStore struct {
	db *sql.DB
}

func newGatewayBlobStore(db *sql.DB) *gatewayBlobStore {
	return &gatewayBlobStore{db: db}
}

// Get is part of the clawpatrol plugin API.
func (s *gatewayBlobStore) Get(kind, name string) ([]byte, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, fmt.Errorf("blob store: no db")
	}
	var value []byte
	err := s.db.QueryRow(
		`SELECT value FROM gateway_blobs WHERE kind = ? AND name = ?`,
		kind, name,
	).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return value, true, nil
}

// Put is part of the clawpatrol plugin API.
func (s *gatewayBlobStore) Put(kind, name string, data []byte) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("blob store: no db")
	}
	_, err := s.db.Exec(
		`INSERT INTO gateway_blobs (kind, name, value, updated_ns)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(kind, name) DO UPDATE SET
		   value = excluded.value, updated_ns = excluded.updated_ns`,
		kind, name, data, time.Now().UnixNano(),
	)
	return err
}

// registerOAuthCredentials walks the loaded policy and registers each
// OAuth-flow credential with the OAuthRegistry under its bare name.
// The OAuth flow data (auth/token URLs, scopes, client id) lives on
// the credential plugin itself via the OAuthFlow() method — see
// config/plugins/credentials/oauth_flows.go.
//
// Re-hydrates existing tokens from the credentials table after
// registration, so policy reloads / first-boot don't lose tokens
// that pre-date this gateway process. Idempotent — safe on every
// config reload.
func registerOAuthCredentials(reg *OAuthRegistry, policy *config.CompiledPolicy) {
	if reg == nil || policy == nil {
		return
	}
	for name, ent := range policy.Credentials {
		fp, ok := ent.Body.(config.OAuthFlowProvider)
		if !ok {
			continue
		}
		flow := fp.OAuthFlow()
		if flow == nil {
			continue
		}
		copied := *flow
		copied.ID = name
		reg.Register(name, copied)
	}
	if err := reg.LoadFromDB(); err != nil {
		log.Printf("oauth: rehydrate from db: %v", err)
	}
}
