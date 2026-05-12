package credentials

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config/runtime"
)

// withFakeOpReader swaps the package-level opReader for the duration of
// the test and restores it on cleanup. Tests register their fake
// inside the returned function — see usage below.
func withFakeOpReader(t *testing.T, fake func(ctx context.Context, ref string) (string, error)) {
	t.Helper()
	prev := opReader
	opReader = fake
	t.Cleanup(func() { opReader = prev })
}

func TestOnePasswordInjectStampsBearerHeader(t *testing.T) {
	withFakeOpReader(t, func(_ context.Context, ref string) (string, error) {
		if ref != "op://Vault/Item/field" {
			t.Errorf("op read got ref %q", ref)
		}
		// realOpRead trims its own output; the fake mirrors the
		// post-trim value the cache expects to see.
		return "sk-test-12345", nil
	})

	cred := &OnePassword{Ref: "op://Vault/Item/field"}
	sec, err := cred.FetchSecret(context.Background())
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	if got := string(sec.Bytes); got != "sk-test-12345" {
		t.Fatalf("secret bytes = %q, want %q", got, "sk-test-12345")
	}

	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	if err := cred.InjectHTTP(req.Context(), req, sec); err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test-12345" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-test-12345")
	}
}

func TestOnePasswordCustomHeaderAndPrefix(t *testing.T) {
	withFakeOpReader(t, func(context.Context, string) (string, error) {
		return "raw-key", nil
	})
	prefix := ""
	cred := &OnePassword{
		Ref:    "op://Vault/Item/field",
		Header: "X-API-Key",
		Prefix: &prefix,
	}
	sec, err := cred.FetchSecret(context.Background())
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	if err := cred.InjectHTTP(req.Context(), req, sec); err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	if got := req.Header.Get("X-API-Key"); got != "raw-key" {
		t.Errorf("X-API-Key = %q, want %q", got, "raw-key")
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty, got %q", got)
	}
}

// TestOnePasswordCustomHeaderWithDefaultPrefix confirms that omitting
// Prefix on a custom Header stamps the secret verbatim (no "Bearer "
// leak). The default-bearer-prefix only applies to the default-
// Authorization header.
func TestOnePasswordCustomHeaderWithDefaultPrefix(t *testing.T) {
	withFakeOpReader(t, func(context.Context, string) (string, error) {
		return "raw-key", nil
	})
	cred := &OnePassword{
		Ref:    "op://Vault/Item/field",
		Header: "X-API-Key",
	}
	sec, _ := cred.FetchSecret(context.Background())
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	if err := cred.InjectHTTP(req.Context(), req, sec); err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	if got := req.Header.Get("X-API-Key"); got != "raw-key" {
		t.Errorf("X-API-Key = %q, want %q", got, "raw-key")
	}
}

// TestOnePasswordCacheHitsAvoidExtraOpReads runs five fetches
// back-to-back; only the first should invoke the CLI. The cache is
// per-credential instance, so reusing the same struct exercises the
// cache path.
func TestOnePasswordCacheHitsAvoidExtraOpReads(t *testing.T) {
	var calls atomic.Int32
	withFakeOpReader(t, func(context.Context, string) (string, error) {
		calls.Add(1)
		return "v", nil
	})
	cred := &OnePassword{Ref: "op://x/y/z", TTL: "1m", parsedTTL: time.Minute}
	for i := 0; i < 5; i++ {
		if _, err := cred.FetchSecret(context.Background()); err != nil {
			t.Fatalf("FetchSecret #%d: %v", i, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("op reader invoked %d times, want 1 (cache miss expected only on first call)", n)
	}
}

// TestOnePasswordCacheExpires drives the cache past its TTL and
// confirms a second op invocation. Uses parsedTTL directly so the test
// doesn't burn real wall-clock time.
func TestOnePasswordCacheExpires(t *testing.T) {
	var calls atomic.Int32
	withFakeOpReader(t, func(context.Context, string) (string, error) {
		calls.Add(1)
		return "v", nil
	})
	cred := &OnePassword{Ref: "op://x/y/z", parsedTTL: time.Nanosecond}
	if _, err := cred.FetchSecret(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := cred.FetchSecret(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("op reader invoked %d times, want 2 after TTL expiry", n)
	}
}

// TestOnePasswordFetchErrorPropagates confirms op-fetch errors flow
// back as errors, NOT as an empty secret. The dispatcher relies on
// this to short-circuit into a 502 instead of forwarding upstream.
func TestOnePasswordFetchErrorPropagates(t *testing.T) {
	withFakeOpReader(t, func(context.Context, string) (string, error) {
		return "", errors.New("op read: exit 1: not signed in")
	})
	cred := &OnePassword{Ref: "op://x/y/z"}
	_, err := cred.FetchSecret(context.Background())
	if err == nil {
		t.Fatal("FetchSecret should have returned an error")
	}
	if !strings.Contains(err.Error(), "op://x/y/z") {
		t.Errorf("error %q does not mention the ref", err)
	}
	if !strings.Contains(err.Error(), "not signed in") {
		t.Errorf("error %q does not include the underlying op stderr", err)
	}
}

// TestOnePasswordEmptyRef rejects requests for an unconfigured credential
// rather than silently shelling out to op without an argument.
func TestOnePasswordEmptyRef(t *testing.T) {
	cred := &OnePassword{}
	_, err := cred.FetchSecret(context.Background())
	if err == nil {
		t.Fatal("FetchSecret with empty Ref should error")
	}
}

// TestOnePasswordInjectEmptySecretFailsClosed ensures the runtime
// rejects empty secrets at injection time too. Belt + braces: the
// SecretStore is the primary fail-closed point, but if some other
// path delivered an empty Secret here we still refuse.
func TestOnePasswordInjectEmptySecretFailsClosed(t *testing.T) {
	cred := &OnePassword{Ref: "op://x/y/z"}
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	if err := cred.InjectHTTP(req.Context(), req, runtime.Secret{}); err == nil {
		t.Fatal("InjectHTTP with empty secret should error")
	}
}

// TestOnePasswordImplementsRuntimeContracts is a compile-time-style
// check that we wire the right interfaces. If a future refactor drops
// one, this fails noisily rather than silently disabling 1password.
func TestOnePasswordImplementsRuntimeContracts(t *testing.T) {
	var _ runtime.HTTPCredentialRuntime = (*OnePassword)(nil)
	var _ runtime.SecretSourceProvider = (*OnePassword)(nil)
}
