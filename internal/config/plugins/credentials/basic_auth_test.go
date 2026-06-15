package credentials

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestBasicAuthInjectHTTPStampsAuthorization(t *testing.T) {
	plugin := &BasicAuth{Username: "agent"}
	req, err := http.NewRequest("GET", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:PH_password")))

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte("real-password")}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("agent:real-password"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestBasicAuthInjectHTTPIgnoresEmptySecret(t *testing.T) {
	plugin := &BasicAuth{Username: "agent"}
	req, err := http.NewRequest("GET", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Basic placeholder")

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Basic placeholder" {
		t.Fatalf("Authorization = %q, want original placeholder", got)
	}
}

func TestBasicAuthSecretSlots(t *testing.T) {
	slots := (&BasicAuth{}).SecretSlots()
	if len(slots) != 1 {
		t.Fatalf("want 1 slot, got %d", len(slots))
	}
	if slots[0].Name != "" {
		t.Errorf("slot name = %q, want unnamed password slot", slots[0].Name)
	}
	if slots[0].Label != "Password" || slots[0].Description == "" {
		t.Errorf("slot missing label/description: %+v", slots[0])
	}
}
