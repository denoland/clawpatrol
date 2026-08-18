package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type testSecretSlots []config.SecretSlot

func (s testSecretSlots) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot(s)
}

// testVerifyingCredential combines SecretSlots with a configurable
// CredentialVerifier so the save handler's verification branch can be
// exercised without depending on a specific plugin.
type testVerifyingCredential struct {
	slots []config.SecretSlot
	err   error
	seen  runtime.Secret
}

func (c *testVerifyingCredential) SecretSlots() []config.SecretSlot { return c.slots }

func (c *testVerifyingCredential) VerifyCredential(_ context.Context, sec runtime.Secret) error {
	c.seen = sec
	return c.err
}

func TestAPICredentialsSetPreservesUntouchedSlotsAndClearsExplicitEmpty(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for slot, value := range map[string]string{
		"cert": "old-cert",
		"key":  "old-key",
		"ca":   "old-ca",
	} {
		if err := setCredentialSlot(db, "client-tls", slot, value); err != nil {
			t.Fatalf("seed slot %q: %v", slot, err)
		}
	}

	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{
			"client-tls": {
				Body: testSecretSlots{
					{Name: "cert", Label: "Client certificate"},
					{Name: "key", Label: "Client key"},
					{Name: "ca", Label: "CA certificate"},
				},
			},
		},
	})
	w := &webMux{g: g}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/credentials/set",
		strings.NewReader(`{"id":"client-tls","owner":"default","slots":{"cert":"new-cert","ca":""}}`),
	)
	rr := httptest.NewRecorder()
	w.apiCredentialsSet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	sec, ok, err := readCredentialSecrets(db, "client-tls")
	if err != nil {
		t.Fatalf("read secrets: %v", err)
	}
	if !ok {
		t.Fatalf("credential secrets not found")
	}
	if got := sec.Extras["cert"]; got != "new-cert" {
		t.Fatalf("cert slot = %q, want new-cert", got)
	}
	if got := sec.Extras["key"]; got != "old-key" {
		t.Fatalf("key slot = %q, want old-key", got)
	}
	if _, ok := sec.Extras["ca"]; ok {
		t.Fatalf("ca slot was preserved after explicit empty update")
	}
}

func TestAPICredentialsSetRunsVerifierAndReportsSuccess(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cred := &testVerifyingCredential{
		slots: []config.SecretSlot{{Name: "bot", Label: "Bot token"}},
	}
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{
			"slack-team": {Body: cred, Plugin: &config.Plugin{Type: "slack_tokens"}},
		},
	})
	w := &webMux{g: g}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/credentials/set",
		strings.NewReader(`{"id":"slack-team","slots":{"bot":"xoxb-good"}}`),
	)
	rr := httptest.NewRecorder()
	w.apiCredentialsSet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK       bool   `json:"ok"`
		Verified bool   `json:"verified"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK || !resp.Verified || resp.Error != "" {
		t.Fatalf("response = %+v, want ok+verified", resp)
	}
	if got := cred.seen.Extras["bot"]; got != "xoxb-good" {
		t.Fatalf("verifier saw bot = %q, want xoxb-good", got)
	}
	v, ok := getCredentialVerification(db, "slack-team")
	if !ok {
		t.Fatal("verification row missing after successful save")
	}
	if v.Status != "ok" || v.Error != "" {
		t.Fatalf("verification row = %+v, want status=ok", v)
	}
	// IntegrationRow.Connected must reflect the verification outcome
	// — true for a successful probe.
	row := findIntegrationRow(t, w, "slack-team")
	if !row.Connected {
		t.Fatal("Connected = false after successful verification")
	}
	if row.VerifyError != "" {
		t.Fatalf("VerifyError = %q, want empty after success", row.VerifyError)
	}
}

func TestAPICredentialsSetRunsVerifierAndReportsFailure(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cred := &testVerifyingCredential{
		slots: []config.SecretSlot{{Name: "bot", Label: "Bot token"}},
		err:   errors.New("slack auth.test: invalid_auth"),
	}
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{
			"slack-team": {Body: cred, Plugin: &config.Plugin{Type: "slack_tokens"}},
		},
	})
	w := &webMux{g: g}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/credentials/set",
		strings.NewReader(`{"id":"slack-team","slots":{"bot":"xoxb-bad"}}`),
	)
	rr := httptest.NewRecorder()
	w.apiCredentialsSet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK       bool   `json:"ok"`
		Verified bool   `json:"verified"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("ok = false, response = %+v", resp)
	}
	if resp.Verified {
		t.Fatalf("verified = true, want false on probe failure")
	}
	if !strings.Contains(resp.Error, "invalid_auth") {
		t.Fatalf("error = %q, want it to surface invalid_auth", resp.Error)
	}
	v, ok := getCredentialVerification(db, "slack-team")
	if !ok {
		t.Fatal("verification row missing after failed save")
	}
	if v.Status != "failed" || !strings.Contains(v.Error, "invalid_auth") {
		t.Fatalf("verification row = %+v, want status=failed with invalid_auth", v)
	}
	// Despite slots being persisted, Connected must reflect the
	// failed verification, not stale "tokens are present" optimism.
	row := findIntegrationRow(t, w, "slack-team")
	if row.Connected {
		t.Fatal("Connected = true after failed verification — must reflect failure")
	}
	if !strings.Contains(row.VerifyError, "invalid_auth") {
		t.Fatalf("VerifyError = %q, want it to surface invalid_auth", row.VerifyError)
	}
}

func TestAPICredentialsClearDropsVerification(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := setCredentialSlot(db, "slack-team", "bot", "xoxb-keep"); err != nil {
		t.Fatalf("seed slot: %v", err)
	}
	if err := setCredentialVerification(db, "slack-team", "ok", ""); err != nil {
		t.Fatalf("seed verification: %v", err)
	}

	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{
			"slack-team": {
				Body: &testVerifyingCredential{
					slots: []config.SecretSlot{{Name: "bot", Label: "Bot token"}},
				},
				Plugin: &config.Plugin{Type: "slack_tokens"},
			},
		},
	})
	w := &webMux{g: g}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/credentials/clear",
		strings.NewReader(`{"id":"slack-team"}`),
	)
	rr := httptest.NewRecorder()
	w.apiCredentialsClear(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if _, ok := getCredentialVerification(db, "slack-team"); ok {
		t.Fatal("verification row survived clearCredential")
	}
}

func findIntegrationRow(t *testing.T, w *webMux, id string) IntegrationRow {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rows := w.statusList(req)
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("integration row %q not found in %#v", id, rows)
	return IntegrationRow{}
}
