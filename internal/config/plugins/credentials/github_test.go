package credentials

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestGitHubOAuthInjectHTTPUsesBearerForAPIRequests(t *testing.T) {
	plugin := &GitHubOAuth{}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/denoland/deployng", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte("real.github.token")}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real.github.token" {
		t.Fatalf("Authorization = %q, want Bearer real.github.token", got)
	}
}

func TestGitHubOAuthInjectHTTPUsesBasicForSmartHTTPGit(t *testing.T) {
	for _, tt := range []struct {
		name string
		url  string
	}{
		{
			name: "upload-pack advertisement",
			url:  "https://github.com/denoland/deployng.git/info/refs?service=git-upload-pack",
		},
		{
			name: "receive-pack advertisement",
			url:  "https://github.com/denoland/deployng.git/info/refs?service=git-receive-pack",
		},
		{
			name: "upload-pack RPC",
			url:  "https://github.com/denoland/deployng.git/git-upload-pack",
		},
		{
			name: "receive-pack RPC",
			url:  "https://github.com/denoland/deployng.git/git-receive-pack",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &GitHubOAuth{}
			req, err := http.NewRequest("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			placeholder := base64.StdEncoding.EncodeToString([]byte("avocet-bot:" + phGitHub))
			req.Header.Set("Authorization", "Basic "+placeholder)

			if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte("real.github.token")}); err != nil {
				t.Fatalf("inject: %v", err)
			}
			got := req.Header.Get("Authorization")
			if !strings.HasPrefix(got, "Basic ") {
				t.Fatalf("Authorization = %q, want Basic auth", got)
			}
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
			if err != nil {
				t.Fatalf("decode Basic auth: %v", err)
			}
			if string(decoded) != "avocet-bot:real.github.token" {
				t.Fatalf("decoded Basic auth = %q, want avocet-bot:real.github.token", decoded)
			}
		})
	}
}

func TestGitHubOAuthInjectHTTPUsesFallbackUsernameForSmartHTTPGit(t *testing.T) {
	plugin := &GitHubOAuth{}
	req, err := http.NewRequest("GET", "https://github.com/denoland/deployng.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte("real.github.token")}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	got := req.Header.Get("Authorization")
	if !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic auth", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	if err != nil {
		t.Fatalf("decode Basic auth: %v", err)
	}
	if string(decoded) != "x-access-token:real.github.token" {
		t.Fatalf("decoded Basic auth = %q, want x-access-token:real.github.token", decoded)
	}
}
