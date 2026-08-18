package credentials

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestSlackVerifyCredentialSuccess(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"ok":true,"team":"ACME","user":"clawbot"}`))
	}))
	defer srv.Close()

	orig := slackAuthTestURL
	slackAuthTestURL = srv.URL
	defer func() { slackAuthTestURL = orig }()

	plugin := &SlackTokens{}
	err := plugin.VerifyCredential(t.Context(), runtime.Secret{
		Extras: map[string]string{"bot": "xoxb-good"},
	})
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if gotAuth != "Bearer xoxb-good" {
		t.Fatalf("Authorization = %q, want Bearer xoxb-good", gotAuth)
	}
}

func TestSlackVerifyCredentialFailureSurfacesSlackError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer srv.Close()

	orig := slackAuthTestURL
	slackAuthTestURL = srv.URL
	defer func() { slackAuthTestURL = orig }()

	err := (&SlackTokens{}).VerifyCredential(t.Context(), runtime.Secret{
		Extras: map[string]string{"bot": "xoxb-bad"},
	})
	if err == nil {
		t.Fatal("VerifyCredential err = nil, want failure")
	}
	if !strings.Contains(err.Error(), "invalid_auth") {
		t.Fatalf("err = %v, want it to mention invalid_auth", err)
	}
}

func TestSlackVerifyCredentialNoToken(t *testing.T) {
	err := (&SlackTokens{}).VerifyCredential(t.Context(), runtime.Secret{})
	if err == nil {
		t.Fatal("VerifyCredential with empty secret err = nil, want failure")
	}
}

func TestSlackVerifyCredentialFallsBackToBytes(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = rw.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	orig := slackAuthTestURL
	slackAuthTestURL = srv.URL
	defer func() { slackAuthTestURL = orig }()

	err := (&SlackTokens{}).VerifyCredential(t.Context(), runtime.Secret{
		Bytes: []byte("xoxb-bytes"),
	})
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if gotAuth != "Bearer xoxb-bytes" {
		t.Fatalf("Authorization = %q, want Bearer xoxb-bytes", gotAuth)
	}
}
