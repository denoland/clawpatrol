package credentials

import (
	"errors"
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
	var rejected *runtime.CredentialRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %T, want *runtime.CredentialRejectedError", err)
	}
}

func TestSlackVerifyCredentialTransientIsNotRejection(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"ratelimited", http.StatusTooManyRequests, `{"ok":false,"error":"ratelimited"}`},
		{"5xx", http.StatusBadGateway, `<html>bad gateway</html>`},
		{"ok=false transient", http.StatusOK, `{"ok":false,"error":"internal_error"}`},
		{"ok=false unknown code", http.StatusOK, `{"ok":false,"error":"org_login_required"}`},
		{"403 unrelated code", http.StatusForbidden, `{"ok":false,"error":"team_access_not_granted"}`},
		{"2xx html", http.StatusOK, "<html><body>Just a moment...</body></html>"},
		{"2xx empty", http.StatusOK, ""},
		{"403 bodiless", http.StatusForbidden, ""},
		{"403 html", http.StatusForbidden, "<html>Access denied</html>"},
		{"401 bodiless", http.StatusUnauthorized, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(tc.code)
				_, _ = rw.Write([]byte(tc.body))
			}))
			defer srv.Close()
			orig := slackAuthTestURL
			slackAuthTestURL = srv.URL
			defer func() { slackAuthTestURL = orig }()

			err := (&SlackTokens{}).VerifyCredential(t.Context(), runtime.Secret{
				Extras: map[string]string{"bot": "xoxb-x"},
			})
			if err == nil {
				t.Fatal("err = nil, want error")
			}
			var rejected *runtime.CredentialRejectedError
			if errors.As(err, &rejected) {
				t.Fatalf("err = %v classified as rejection, want plain error", err)
			}
		})
	}
}

// Slack's own error shape on a 401/403 is a verdict.
func TestSlackVerifyCredential401WithSlackErrorIsRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer srv.Close()
	orig := slackAuthTestURL
	slackAuthTestURL = srv.URL
	defer func() { slackAuthTestURL = orig }()

	err := (&SlackTokens{}).VerifyCredential(t.Context(), runtime.Secret{Extras: map[string]string{"bot": "xoxb-x"}})
	var rejected *runtime.CredentialRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %v (%T), want rejection", err, err)
	}
}

// Both tokens are probed; a revoked app token fails the credential
// even when the bot token is fine.
func TestSlackVerifyCredentialProbesAppTokenToo(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		seen = append(seen, auth)
		if auth == "Bearer xapp-revoked" {
			_, _ = rw.Write([]byte(`{"ok":false,"error":"token_revoked"}`))
			return
		}
		_, _ = rw.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	orig := slackAuthTestURL
	slackAuthTestURL = srv.URL
	defer func() { slackAuthTestURL = orig }()

	err := (&SlackTokens{}).VerifyCredential(t.Context(), runtime.Secret{
		Extras: map[string]string{"bot": "xoxb-good", "app": "xapp-revoked"},
	})
	var rejected *runtime.CredentialRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %v (%T), want rejection for the app token", err, err)
	}
	if !strings.Contains(err.Error(), "app token") || !strings.Contains(err.Error(), "token_revoked") {
		t.Fatalf("err = %v, want it to name the app token and token_revoked", err)
	}
	if len(seen) != 2 || seen[0] != "Bearer xoxb-good" || seen[1] != "Bearer xapp-revoked" {
		t.Fatalf("probed %v, want bot then app", seen)
	}
}

func TestSlackVerifyCredentialNoToken(t *testing.T) {
	err := (&SlackTokens{}).VerifyCredential(t.Context(), runtime.Secret{})
	if err == nil {
		t.Fatal("VerifyCredential with empty secret err = nil, want failure")
	}
	var rejected *runtime.CredentialRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %T, want *runtime.CredentialRejectedError (definitive verdict)", err)
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
