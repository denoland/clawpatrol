package credentials

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config/runtime"
)

// stubEKSEndpoint satisfies the awsEKSParams contract so SignHTTPRequest
// can pull cluster + region without us standing up a real
// KubernetesEndpoint.
type stubEKSEndpoint struct {
	cluster string
	region  string
}

func (s *stubEKSEndpoint) AWSEKSAuthParams() (cluster, region string) {
	return s.cluster, s.region
}

// TestAWSCredentialSignHTTPRequestEmitsEKSBearer verifies the
// Authorization header stamped on a kubernetes API request decodes
// back into an STS GetCallerIdentity URL with cluster + region wired
// into the signed payload.
func TestAWSCredentialSignHTTPRequestEmitsEKSBearer(t *testing.T) {
	cred := &AWSCredential{}
	req, err := http.NewRequest("GET", "https://k8s.example/api/v1/namespaces", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	sec := runtime.Secret{
		Extras: map[string]string{
			"access_key_id":     "AKIDEXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		},
	}
	ep := &stubEKSEndpoint{cluster: "my-cluster", region: "us-west-2"}
	if err := cred.SignHTTPRequest(context.Background(), req, sec, ep); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := req.Header.Get("Authorization")
	const wantPrefix = "Bearer k8s-aws-v1."
	if !strings.HasPrefix(auth, wantPrefix) {
		t.Fatalf("Authorization = %q, want prefix %q", auth, wantPrefix)
	}
	encoded := strings.TrimPrefix(auth, wantPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatalf("parse presigned url %q: %v", raw, err)
	}
	if want := "sts.us-west-2.amazonaws.com"; u.Host != want {
		t.Errorf("host = %q, want %q", u.Host, want)
	}
	q := u.Query()
	if got := q.Get("Action"); got != "GetCallerIdentity" {
		t.Errorf("Action = %q, want GetCallerIdentity", got)
	}
	if !strings.Contains(q.Get("X-Amz-SignedHeaders"), "x-k8s-aws-id") {
		t.Errorf("X-Amz-SignedHeaders = %q, must include x-k8s-aws-id (cluster name is part of the signature)", q.Get("X-Amz-SignedHeaders"))
	}
	if got := q.Get("X-Amz-Credential"); !strings.HasPrefix(got, "AKIDEXAMPLE/") {
		t.Errorf("X-Amz-Credential = %q, want prefix AKIDEXAMPLE/", got)
	}
}

func TestAWSCredentialSignHTTPRequestRejectsNonEKSEndpoint(t *testing.T) {
	cred := &AWSCredential{}
	req, err := http.NewRequest("GET", "https://example/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	err = cred.SignHTTPRequest(context.Background(), req, runtime.Secret{
		Extras: map[string]string{"access_key_id": "x", "secret_access_key": "y"},
	}, struct{}{})
	if err == nil || !strings.Contains(err.Error(), "kubernetes") {
		t.Fatalf("err = %v, want one mentioning kubernetes endpoint", err)
	}
}

func TestAWSCredentialSignHTTPRequestRejectsMissingClusterRegion(t *testing.T) {
	cred := &AWSCredential{}
	req, err := http.NewRequest("GET", "https://example/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	err = cred.SignHTTPRequest(context.Background(), req, runtime.Secret{
		Extras: map[string]string{"access_key_id": "x", "secret_access_key": "y"},
	}, &stubEKSEndpoint{cluster: "", region: "us-east-1"})
	if err == nil || !strings.Contains(err.Error(), "cluster_name") {
		t.Fatalf("err = %v, want one mentioning cluster_name", err)
	}
}

func TestAWSCredentialMaterialRequiresKeyAndSecret(t *testing.T) {
	if _, _, _, err := awsCredentialMaterial(runtime.Secret{Extras: map[string]string{"access_key_id": "x"}}); err == nil {
		t.Fatal("expected error when secret_access_key is empty")
	}
	if _, _, _, err := awsCredentialMaterial(runtime.Secret{Extras: map[string]string{"secret_access_key": "y"}}); err == nil {
		t.Fatal("expected error when access_key_id is empty")
	}
	akid, sec, token, err := awsCredentialMaterial(runtime.Secret{Extras: map[string]string{
		"access_key_id":     "x",
		"secret_access_key": "y",
		"session_token":     "z",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if akid != "x" || sec != "y" || token != "z" {
		t.Fatalf("got (%q,%q,%q), want (x,y,z)", akid, sec, token)
	}
}
