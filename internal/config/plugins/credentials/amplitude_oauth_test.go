package credentials

import (
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestAmplitudeOAuthInjectHTTPUsesBearer(t *testing.T) {
	plugin := &AmplitudeOAuth{}
	req, err := http.NewRequest("GET", "https://mcp.eu.amplitude.com/mcp", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte("real.amplitude.token")}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real.amplitude.token" {
		t.Fatalf("Authorization = %q, want Bearer real.amplitude.token", got)
	}
}

func TestAmplitudeOAuthEnvVarsIncludeAmpPlaceholdersAndRegion(t *testing.T) {
	vars := (&AmplitudeOAuth{Region: "eu"}).EnvVars()
	got := map[string]string{}
	for _, v := range vars {
		got[v.Name] = v.Value
	}
	if got["AMPLITUDE_ACCESS_TOKEN"] != phAmplitude {
		t.Fatalf("AMPLITUDE_ACCESS_TOKEN = %q, want %q", got["AMPLITUDE_ACCESS_TOKEN"], phAmplitude)
	}
	if got["AMPLITUDE_OAUTH_TOKEN"] != phAmplitude {
		t.Fatalf("AMPLITUDE_OAUTH_TOKEN = %q, want %q", got["AMPLITUDE_OAUTH_TOKEN"], phAmplitude)
	}
	if got["AMPLITUDE_REGION"] != "eu" {
		t.Fatalf("AMPLITUDE_REGION = %q, want eu", got["AMPLITUDE_REGION"])
	}
}

func TestAmplitudeOAuthFlowUsesEUHostedMCP(t *testing.T) {
	flow := (&AmplitudeOAuth{Region: "eu"}).OAuthFlow()
	if flow.Flow != "dynamic_mcp" {
		t.Fatalf("Flow = %q, want dynamic_mcp", flow.Flow)
	}
	if flow.OAuth.AuthURL != "https://mcp.eu.amplitude.com/authorize" {
		t.Fatalf("AuthURL = %q", flow.OAuth.AuthURL)
	}
	if flow.OAuth.TokenURL != "https://mcp.eu.amplitude.com/token" {
		t.Fatalf("TokenURL = %q", flow.OAuth.TokenURL)
	}
	if flow.OAuth.RegisterURL != "https://mcp.eu.amplitude.com/register" {
		t.Fatalf("RegisterURL = %q", flow.OAuth.RegisterURL)
	}
	if flow.OAuth.RedirectURI != "http://localhost:8900/callback" {
		t.Fatalf("RedirectURI = %q", flow.OAuth.RedirectURI)
	}
	wantScopes := []string{"mcp:read", "mcp:write", "offline_access"}
	if len(flow.OAuth.Scopes) != len(wantScopes) {
		t.Fatalf("Scopes = %#v, want %#v", flow.OAuth.Scopes, wantScopes)
	}
	for i, want := range wantScopes {
		if flow.OAuth.Scopes[i] != want {
			t.Fatalf("Scopes[%d] = %q, want %q", i, flow.OAuth.Scopes[i], want)
		}
	}
}
