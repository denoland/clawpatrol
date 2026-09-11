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
	"time"

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
		err:   &runtime.CredentialRejectedError{Reason: "slack auth.test: invalid_auth"},
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

func TestAPICredentialsSetClearingEverySlotDropsVerification(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := setCredentialSlot(db, "slack-team", "bot", "xoxb-old"); err != nil {
		t.Fatalf("seed slot: %v", err)
	}
	if err := setCredentialVerification(db, "slack-team", "failed", "slack auth.test: invalid_auth"); err != nil {
		t.Fatalf("seed verification: %v", err)
	}

	cred := &testVerifyingCredential{
		slots: []config.SecretSlot{{Name: "bot", Label: "Bot token"}},
		err:   errors.New("no bot token to verify"),
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
		strings.NewReader(`{"id":"slack-team","slots":{"bot":""}}`),
	)
	rr := httptest.NewRecorder()
	w.apiCredentialsSet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, has := resp["verified"]; has {
		t.Fatalf("response = %v, want no verified field when nothing is stored", resp)
	}
	if cred.seen.Extras != nil || cred.seen.Bytes != nil {
		t.Fatalf("verifier was invoked with %+v, want it skipped", cred.seen)
	}
	if _, ok := getCredentialVerification(db, "slack-team"); ok {
		t.Fatal("stale verification row survived clearing every slot")
	}
	row := findIntegrationRow(t, w, "slack-team")
	if row.Connected || row.VerifyError != "" {
		t.Fatalf("row = %+v, want disconnected with no verify error", row)
	}
}

// A probe that cannot reach a verdict (transport error, timeout, 5xx)
// must not be recorded as a failure: the previous row survives, and
// the response flags the save as unverified.
func TestAPICredentialsSetUnreachableProviderKeepsLastKnownState(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cred := &testVerifyingCredential{
		slots: []config.SecretSlot{{Name: "bot", Label: "Bot token"}},
		err:   errors.New(`Post "https://slack.com/api/auth.test": dial tcp: connection refused`),
	}
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{
			"slack-team": {Body: cred, Plugin: &config.Plugin{Type: "slack_tokens"}},
		},
	})
	w := &webMux{g: g}

	post := func() map[string]any {
		t.Helper()
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/credentials/set",
			strings.NewReader(`{"id":"slack-team","slots":{"bot":"xoxb-maybe"}}`),
		)
		rr := httptest.NewRecorder()
		w.apiCredentialsSet(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp["verified"] != false || resp["unverified"] != true {
			t.Fatalf("response = %v, want verified=false unverified=true", resp)
		}
		if e, _ := resp["error"].(string); !strings.HasPrefix(e, "could not verify: ") {
			t.Fatalf("error = %q, want could not verify prefix", e)
		}
		return resp
	}

	// No prior row: nothing is stored, status falls back to slot
	// presence.
	post()
	if _, ok := getCredentialVerification(db, "slack-team"); ok {
		t.Fatal("unverified probe stored a verification row")
	}
	if row := findIntegrationRow(t, w, "slack-team"); !row.Connected || row.VerifyError != "" {
		t.Fatalf("row = %+v, want slot-presence connected with no verify error", row)
	}

	// Prior ok row survives an outage.
	if err := setCredentialVerification(db, "slack-team", "ok", ""); err != nil {
		t.Fatalf("seed verification: %v", err)
	}
	post()
	if v, ok := getCredentialVerification(db, "slack-team"); !ok || v.Status != "ok" {
		t.Fatalf("verification row = %+v (ok=%v), want prior ok row untouched", v, ok)
	}

	// Prior failed row survives too — an outage is not a pass.
	if err := setCredentialVerification(db, "slack-team", "failed", "slack auth.test: invalid_auth"); err != nil {
		t.Fatalf("seed verification: %v", err)
	}
	post()
	if v, ok := getCredentialVerification(db, "slack-team"); !ok || v.Status != "failed" {
		t.Fatalf("verification row = %+v (ok=%v), want prior failed row untouched", v, ok)
	}

	// Changed material + no verdict: the old row described bytes that
	// are gone. Drop it and fall back to slot presence.
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/credentials/set",
		strings.NewReader(`{"id":"slack-team","slots":{"bot":"xoxb-different"}}`),
	)
	rr := httptest.NewRecorder()
	w.apiCredentialsSet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if v, ok := getCredentialVerification(db, "slack-team"); ok {
		t.Fatalf("verification row = %+v survived a save that changed the material", v)
	}
	if row := findIntegrationRow(t, w, "slack-team"); !row.Connected || row.VerifyError != "" {
		t.Fatalf("row = %+v, want slot-presence connected with no verify error", row)
	}
}

func TestAPICredentialsClearRejectsUnknownID(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{Credentials: map[string]*config.Entity{}})
	w := &webMux{g: g}

	req := httptest.NewRequest(http.MethodPost, "/api/credentials/clear", strings.NewReader(`{"id":"nope"}`))
	rr := httptest.NewRecorder()
	w.apiCredentialsClear(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if _, ok := g.credSaveLocks.Load("nope"); ok {
		t.Fatal("unknown id created a save-lock entry")
	}
}

func TestSetCredentialVerificationTruncatesReason(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	long := strings.Repeat("x", 1000)
	if err := setCredentialVerification(db, "c", "failed", long); err != nil {
		t.Fatalf("set: %v", err)
	}
	v, ok := getCredentialVerification(db, "c")
	if !ok || len(v.Error) > verifyReasonMax+len("…") || !strings.HasSuffix(v.Error, "…") {
		t.Fatalf("stored error len=%d %q…, want truncated to %d", len(v.Error), v.Error[:20], verifyReasonMax)
	}
}

// blockingVerifier parks inside VerifyCredential until released so a
// test can hold one save open while a second one arrives.
type blockingVerifier struct {
	slots   []config.SecretSlot
	entered chan string // token seen, sent on entry
	release chan struct{}
	verdict func(tok string) error
}

func (b *blockingVerifier) SecretSlots() []config.SecretSlot { return b.slots }

func (b *blockingVerifier) VerifyCredential(_ context.Context, sec runtime.Secret) error {
	tok := sec.Extras["bot"]
	b.entered <- tok
	<-b.release
	return b.verdict(tok)
}

// Overlapping saves for one credential are serialised: the second
// save's probe does not start until the first has recorded its
// verdict, so the row always reflects the most recent save.
func TestAPICredentialsSetSerialisesPerCredential(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cred := &blockingVerifier{
		slots:   []config.SecretSlot{{Name: "bot", Label: "Bot token"}},
		entered: make(chan string, 2),
		release: make(chan struct{}),
		verdict: func(tok string) error {
			if tok == "xoxb-bad" {
				return &runtime.CredentialRejectedError{Reason: "slack auth.test: invalid_auth"}
			}
			return nil
		},
	}
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{
			"slack-team": {Body: cred, Plugin: &config.Plugin{Type: "slack_tokens"}},
		},
	})
	w := &webMux{g: g}

	save := func(tok string) <-chan *httptest.ResponseRecorder {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			req := httptest.NewRequest(
				http.MethodPost,
				"/api/credentials/set",
				strings.NewReader(`{"id":"slack-team","slots":{"bot":"`+tok+`"}}`),
			)
			rr := httptest.NewRecorder()
			w.apiCredentialsSet(rr, req)
			done <- rr
		}()
		return done
	}

	if err := setCredentialVerification(db, "slack-team", "ok", ""); err != nil {
		t.Fatalf("seed verification: %v", err)
	}
	first := save("xoxb-good")
	if tok := <-cred.entered; tok != "xoxb-good" {
		t.Fatalf("first probe saw %q", tok)
	}
	// New material is being probed: the old ok verdict must already be
	// gone so a crash here cannot leave it attached to these bytes.
	if v, ok := getCredentialVerification(db, "slack-team"); ok {
		t.Fatalf("verification row = %+v still present while probing changed material", v)
	}
	second := save("xoxb-bad")
	select {
	case tok := <-cred.entered:
		t.Fatalf("second save probed %q while the first was still in flight", tok)
	case <-time.After(100 * time.Millisecond):
	}
	// Even though the second save is queued behind the lock, the
	// first probe still sees the first token: the slots were written
	// under the lock, so the second write has not happened yet.
	if sec, _, _ := readCredentialSecrets(db, "slack-team"); sec.Extras["bot"] != "xoxb-good" {
		t.Fatalf("stored bot = %q during first save, want xoxb-good", sec.Extras["bot"])
	}
	cred.release <- struct{}{}
	if rr := <-first; rr.Code != http.StatusOK {
		t.Fatalf("first save status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if tok := <-cred.entered; tok != "xoxb-bad" {
		t.Fatalf("second probe saw %q", tok)
	}
	cred.release <- struct{}{}
	if rr := <-second; rr.Code != http.StatusOK {
		t.Fatalf("second save status = %d, body = %s", rr.Code, rr.Body.String())
	}
	v, ok := getCredentialVerification(db, "slack-team")
	if !ok || v.Status != "failed" {
		t.Fatalf("verification row = %+v (ok=%v), want failed from the later save", v, ok)
	}
}
