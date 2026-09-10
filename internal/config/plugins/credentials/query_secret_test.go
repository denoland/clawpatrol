package credentials

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Secrets must travel in headers, never in the URL, and a placeholder
// the agent put in the query string must not reach upstream.
func TestClickhouseInjectKeepsSecretOutOfQuery(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://ch.example.test/?query=SELECT+1&user=PH_user&password=PH_pw", strings.NewReader("SELECT 1"))
	c := &ClickhouseCredential{User: "svc"}
	if err := c.InjectHTTP(context.Background(), req, runtime.Secret{Bytes: []byte("s3cret")}); err != nil {
		t.Fatal(err)
	}
	if u, p, ok := req.BasicAuth(); !ok || u != "svc" || p != "s3cret" {
		t.Fatalf("basic auth = %q %q %v", u, p, ok)
	}
	q := req.URL.Query()
	if q.Has("user") || q.Has("password") {
		t.Fatalf("query still carries auth: %q", req.URL.RawQuery)
	}
	if q.Get("query") != "SELECT 1" {
		t.Fatalf("unrelated query param lost: %q", req.URL.RawQuery)
	}
	if strings.Contains(req.URL.String(), "s3cret") {
		t.Fatalf("secret in URL: %s", req.URL)
	}
}

func TestGeminiInjectKeepsSecretOutOfQuery(t *testing.T) {
	for _, raw := range []string{
		"https://generativelanguage.googleapis.com/v1beta/models?key=PH_gemini",
		"https://generativelanguage.googleapis.com/v1beta/models",
	} {
		req, _ := http.NewRequest("GET", raw, nil)
		g := &GeminiAPIKey{}
		if err := g.InjectHTTP(context.Background(), req, runtime.Secret{Bytes: []byte("AIza-secret")}); err != nil {
			t.Fatal(err)
		}
		if req.Header.Get("x-goog-api-key") != "AIza-secret" {
			t.Fatalf("%s: header not set", raw)
		}
		if req.URL.Query().Has("key") {
			t.Fatalf("%s: ?key survived: %q", raw, req.URL.RawQuery)
		}
		if strings.Contains(req.URL.String(), "secret") {
			t.Fatalf("%s: secret in URL", raw)
		}
	}
}
