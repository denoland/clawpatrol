package credentials

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestDiscordVerifyCredentialSuccess(t *testing.T) {
	var gotAuth, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
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
}

func TestDiscordVerifyCredentialNoToken(t *testing.T) {
	err := (&DiscordBotToken{}).VerifyCredential(t.Context(), runtime.Secret{})
	if err == nil {
		t.Fatal("VerifyCredential with empty secret err = nil, want failure")
	}
}
