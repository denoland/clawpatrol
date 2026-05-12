package main

// Tests for the env_pushdown runtime substitution layer. The config-
// loader half is covered by golden fixtures under config/testdata
// (feature_env_pushdown.* / error_env_pushdown_*); these tests
// exercise the gateway-side path: building a CompiledPolicy with
// env_pushdown entries, swapping placeholders on outbound HTTP
// requests, and asserting that the dashboard request-body sample
// captures the pre-substitution bytes (so the operator never sees
// the real secret in the SSE / OTel stream).

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// fakeSecrets is a runtime.SecretStore stub that returns whatever
// the test parked in `byName`. Plenty of tests in this package
// already need a SecretStore that doesn't touch a real DB; this
// minimal impl is local to the env_pushdown tests to avoid
// accidental coupling with the gateway's main store.
type fakeSecrets struct {
	byName map[string][]byte
}

func (f *fakeSecrets) Get(name string) (runtime.Secret, error) {
	if v, ok := f.byName[name]; ok {
		return runtime.Secret{Bytes: v}, nil
	}
	return runtime.Secret{}, nil
}

// newEnvPushdownGateway builds a minimal *Gateway with an in-memory
// CompiledPolicy carrying the supplied env_pushdown entries plus a
// fake secret store. The DB / sinks / dashboard infrastructure stay
// nil — only the substitution path is under test.
func newEnvPushdownGateway(t *testing.T, entries []*config.EnvPushdownEntry, secrets map[string][]byte) *Gateway {
	t.Helper()
	g := &Gateway{
		db:      (*sql.DB)(nil),
		secrets: &fakeSecrets{byName: secrets},
	}
	cp := &config.CompiledPolicy{EnvPushdown: entries}
	g.policy.Store(cp)
	return g
}

func TestApplyEnvPushdownURLHeaders_SwapsPlaceholderInHeader(t *testing.T) {
	entry := &config.EnvPushdownEntry{Name: "OPENAI_API_KEY", SecretRef: "openai_key"}
	g := newEnvPushdownGateway(t, []*config.EnvPushdownEntry{entry}, map[string][]byte{
		"openai_key": []byte("sk-real-openai-secret"),
	})

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+entry.Placeholder())

	g.applyEnvPushdownURLHeaders(req, "default")

	got := req.Header.Get("Authorization")
	if !strings.Contains(got, "sk-real-openai-secret") {
		t.Errorf("Authorization not swapped: %q", got)
	}
	if strings.Contains(got, entry.Placeholder()) {
		t.Errorf("placeholder bytes still present after swap: %q", got)
	}
}

func TestApplyEnvPushdownURLHeaders_SwapsPlaceholderInURLQuery(t *testing.T) {
	entry := &config.EnvPushdownEntry{Name: "GOOGLE_API_KEY", SecretRef: "google_key"}
	g := newEnvPushdownGateway(t, []*config.EnvPushdownEntry{entry}, map[string][]byte{
		"google_key": []byte("AIzaReal-Google-Key"),
	})

	req, err := http.NewRequest("GET", "https://generativelanguage.googleapis.com/v1/models?key="+entry.Placeholder(), nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	g.applyEnvPushdownURLHeaders(req, "default")

	if !strings.Contains(req.URL.RawQuery, "AIzaReal-Google-Key") {
		t.Errorf("URL query not swapped: %q", req.URL.RawQuery)
	}
	if strings.Contains(req.URL.RawQuery, entry.Placeholder()) {
		t.Errorf("placeholder bytes still present after swap: %q", req.URL.RawQuery)
	}
}

func TestApplyEnvPushdownBody_SwapsPlaceholderInBody(t *testing.T) {
	entry := &config.EnvPushdownEntry{Name: "OPENAI_API_KEY", SecretRef: "openai_key"}
	g := newEnvPushdownGateway(t, []*config.EnvPushdownEntry{entry}, map[string][]byte{
		"openai_key": []byte("sk-real-openai"),
	})

	body := `{"api_key":"` + entry.Placeholder() + `","prompt":"hi"}`
	req, err := http.NewRequest("POST", "https://example.com/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}

	if !g.applyEnvPushdownBody(req, "default") {
		t.Fatal("expected substitution to happen")
	}

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Contains(got, []byte("sk-real-openai")) {
		t.Errorf("body not swapped: %s", got)
	}
	if bytes.Contains(got, []byte(entry.Placeholder())) {
		t.Errorf("placeholder bytes still present: %s", got)
	}
	if int64(len(got)) != req.ContentLength {
		t.Errorf("ContentLength not updated: got %d want %d", req.ContentLength, len(got))
	}
}

func TestApplyEnvPushdownBody_NoEntriesIsNoOp(t *testing.T) {
	g := newEnvPushdownGateway(t, nil, nil)
	body := `{"prompt":"hi"}`
	req, _ := http.NewRequest("POST", "https://example.com/", strings.NewReader(body))
	if g.applyEnvPushdownBody(req, "default") {
		t.Fatal("expected no-op when no env_pushdown entries declared")
	}
}

func TestApplyEnvPushdownBody_ValueFormIsNotSubstituted(t *testing.T) {
	// `value = "..."` entries are operator-declared literals, not
	// secrets to swap. The gateway shouldn't try to substitute on
	// them — they reach the agent's env verbatim.
	entry := &config.EnvPushdownEntry{Name: "AWS_REGION", Literal: "us-east-1", HasLiteral: true}
	g := newEnvPushdownGateway(t, []*config.EnvPushdownEntry{entry}, map[string][]byte{})
	body := `{"region":"us-east-1"}`
	req, _ := http.NewRequest("POST", "https://example.com/", strings.NewReader(body))
	if g.applyEnvPushdownBody(req, "default") {
		t.Fatal("value-form entries should not trigger body substitution")
	}
}

func TestApplyEnvPushdownBody_MissingSecretLeavesPlaceholder(t *testing.T) {
	// When the secret store has no bytes for the credential, the
	// gateway forwards the placeholder verbatim and the request
	// reaches the upstream with a clearly-not-a-real-key value.
	// Better than swapping in an empty string (which some SDKs treat
	// as "no auth" and produce a confusing upstream 401 chain).
	entry := &config.EnvPushdownEntry{Name: "OPENAI_API_KEY", SecretRef: "openai_key"}
	g := newEnvPushdownGateway(t, []*config.EnvPushdownEntry{entry}, map[string][]byte{
		// intentionally no openai_key
	})

	body := `{"api_key":"` + entry.Placeholder() + `"}`
	req, _ := http.NewRequest("POST", "https://example.com/", strings.NewReader(body))
	g.applyEnvPushdownBody(req, "default")
	got, _ := io.ReadAll(req.Body)
	if !bytes.Contains(got, []byte(entry.Placeholder())) {
		t.Errorf("placeholder should pass through when secret missing: %s", got)
	}
}

func TestEnvPushdownPlaceholderDeterministic(t *testing.T) {
	// Placeholder string must be stable across reloads — test
	// fixtures depend on it and the dashboard inspector embeds it
	// in the redacted output.
	e := &config.EnvPushdownEntry{Name: "FOO"}
	if e.Placeholder() != "clawpatrol-env-pushdown-FOO-placeholder-do-not-use" {
		t.Errorf("unexpected placeholder: %q", e.Placeholder())
	}
}

// assertNoLogPanic confirms the resolver doesn't panic when the
// store returns an error. Used to be: g.secrets.Get could return
// (Secret{}, err) and the resolver dereferenced sec.Bytes anyway.
// Now it logs + caches a nil.
func TestEnvPushdownResolverHandlesStoreError(t *testing.T) {
	g := &Gateway{secrets: &errSecrets{}}
	g.policy.Store(&config.CompiledPolicy{})

	r := g.envPushdownResolver("default")
	if r("openai_key") != nil {
		t.Errorf("resolver should return nil on store error")
	}
}

type errSecrets struct{ calls atomic.Int64 }

func (e *errSecrets) Get(_ string) (runtime.Secret, error) {
	e.calls.Add(1)
	return runtime.Secret{}, io.EOF
}
