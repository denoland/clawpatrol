package credentials

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestDiscordVerifyCredentialSuccess(t *testing.T) {
	var gotAuth, gotMethod, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotUA = r.Header.Get("User-Agent")
		_, _ = rw.Write([]byte(`{"id":"1","username":"clawbot"}`))
	}))
	defer srv.Close()

	orig := discordUsersMeURL
	discordUsersMeURL = srv.URL
	defer func() { discordUsersMeURL = orig }()

	err := (&DiscordBotToken{}).VerifyCredential(t.Context(), runtime.Secret{
		Bytes: []byte("real.discord.token"),
	})
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if gotMethod != "GET" {
		t.Fatalf("method = %q, want GET", gotMethod)
	}
	if gotAuth != "Bot real.discord.token" {
		t.Fatalf("Authorization = %q, want Bot real.discord.token", gotAuth)
	}
	if gotUA != "clawpatrol/verify" {
		t.Fatalf("User-Agent = %q, want clawpatrol/verify", gotUA)
	}
}

// A 2xx that is not Discord's user object (CDN challenge page, empty
// body, JSON without an id) is not a pass, and a 401/403 without
// Discord's JSON error shape is not a rejection: both are "no
// verdict".
func TestDiscordVerifyCredentialNonAPIBodiesAreNotVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"2xx html", http.StatusOK, "<html><body>Just a moment...</body></html>"},
		{"2xx empty", http.StatusOK, ""},
		{"2xx json without id", http.StatusOK, `{"username":"x"}`},
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
			orig := discordUsersMeURL
			discordUsersMeURL = srv.URL
			defer func() { discordUsersMeURL = orig }()

			err := (&DiscordBotToken{}).VerifyCredential(t.Context(), runtime.Secret{Bytes: []byte("tok")})
			if err == nil {
				t.Fatal("err = nil, want no-verdict error")
			}
			var rejected *runtime.CredentialRejectedError
			if errors.As(err, &rejected) {
				t.Fatalf("err = %v classified as rejection, want plain error", err)
			}
		})
	}
}

func TestDiscordVerifyCredentialFailureSurfacesDiscordMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte(`{"code":0,"message":"401: Unauthorized"}`))
	}))
	defer srv.Close()

	orig := discordUsersMeURL
	discordUsersMeURL = srv.URL
	defer func() { discordUsersMeURL = orig }()

	err := (&DiscordBotToken{}).VerifyCredential(t.Context(), runtime.Secret{
		Bytes: []byte("bad.token"),
	})
	if err == nil {
		t.Fatal("VerifyCredential err = nil, want failure")
	}
	if !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("err = %v, want it to mention Unauthorized", err)
	}
	var rejected *runtime.CredentialRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %T, want *runtime.CredentialRejectedError", err)
	}
}

func TestDiscordVerifyCredentialServerErrorIsNotRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rw.Write([]byte(`{"message":"503: Service Unavailable","code":0}`))
	}))
	defer srv.Close()

	orig := discordUsersMeURL
	discordUsersMeURL = srv.URL
	defer func() { discordUsersMeURL = orig }()

	err := (&DiscordBotToken{}).VerifyCredential(t.Context(), runtime.Secret{Bytes: []byte("tok")})
	if err == nil {
		t.Fatal("err = nil, want error")
	}
	var rejected *runtime.CredentialRejectedError
	if errors.As(err, &rejected) {
		t.Fatalf("err = %v classified as rejection, want plain error", err)
	}
}

func TestDiscordVerifyCredentialNoToken(t *testing.T) {
	err := (&DiscordBotToken{}).VerifyCredential(t.Context(), runtime.Secret{})
	if err == nil {
		t.Fatal("VerifyCredential with empty secret err = nil, want failure")
	}
	var rejected *runtime.CredentialRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %T, want *runtime.CredentialRejectedError (definitive verdict)", err)
	}
}
