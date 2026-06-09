package runtime_test

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestEnvSecretStore_AWSParts verifies the AWS credential slots are
// reachable via the CLAWPATROL_SECRET_<NAME>_<SLOT> env-var path. The
// suffix lowercased is the Extras key aws_credential reads, so
// ACCESS_KEY_ID must land in Extras["access_key_id"], etc.
func TestEnvSecretStore_AWSParts(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("CLAWPATROL_SECRET_AWS_SECRET_ACCESS_KEY", "secret-material")
	t.Setenv("CLAWPATROL_SECRET_AWS_SESSION_TOKEN", "session-token")

	sec, err := runtime.EnvSecretStore{}.Get("aws")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for key, want := range map[string]string{
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "secret-material",
		"session_token":     "session-token",
	} {
		if got := sec.Extras[key]; got != want {
			t.Errorf("Extras[%q] = %q, want %q", key, got, want)
		}
	}
}

// TestEnvSecretStore_MTLSParts guards the original cert/key/ca suffixes
// so extending envParts for AWS didn't regress the mtls path.
func TestEnvSecretStore_MTLSParts(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_MTLS_CERT", "cert-pem")
	t.Setenv("CLAWPATROL_SECRET_MTLS_KEY", "key-pem")
	t.Setenv("CLAWPATROL_SECRET_MTLS_CA", "ca-pem")

	sec, err := runtime.EnvSecretStore{}.Get("mtls")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for key, want := range map[string]string{
		"cert": "cert-pem",
		"key":  "key-pem",
		"ca":   "ca-pem",
	} {
		if got := sec.Extras[key]; got != want {
			t.Errorf("Extras[%q] = %q, want %q", key, got, want)
		}
	}
}
