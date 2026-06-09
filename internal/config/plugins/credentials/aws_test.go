package credentials

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
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
	if got := q.Get("X-Amz-Expires"); got != "60" {
		t.Errorf("X-Amz-Expires = %q, want 60 (aws-iam-authenticator rejects presigned URLs without an expiration)", got)
	}
}

// TestAWSCredentialReSignsNonEKSRequest verifies that a proxied
// `*.amazonaws.com` request bound to a non-EKS endpoint is re-signed
// with the gateway's creds: the client's placeholder Authorization /
// X-Amz-Security-Token are replaced, service + region come from the
// incoming credential scope, and the reused content hash is signed over.
func TestAWSCredentialReSignsNonEKSRequest(t *testing.T) {
	cred := &AWSCredential{}
	req, err := http.NewRequest("POST", "https://dynamodb.eu-west-1.amazonaws.com/", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	const contentHash = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	// The agent's aws-cli signed with placeholder creds: scope names the
	// real service (dynamodb) + region (us-west-2), which must win over
	// the hostname's eu-west-1.
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIACLAWPATROLPLACE0/20260609/us-west-2/dynamodb/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef")
	req.Header.Set("X-Amz-Content-Sha256", contentHash)
	req.Header.Set("X-Amz-Security-Token", "placeholder-session-token")

	sec := runtime.Secret{Extras: map[string]string{
		"access_key_id":     "AKIDEXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}}
	if err := cred.SignHTTPRequest(context.Background(), req, sec, struct{}{}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization = %q, want a fresh SigV4 signature", auth)
	}
	if strings.Contains(auth, "deadbeef") {
		t.Errorf("Authorization still carries the client signature: %q", auth)
	}
	if got := "AKIDEXAMPLE/"; !strings.Contains(auth, "Credential="+got) {
		t.Errorf("Authorization = %q, want gateway key %q in credential scope", auth, got)
	}
	if !strings.Contains(auth, "/us-west-2/dynamodb/aws4_request") {
		t.Errorf("Authorization = %q, want scope from the incoming credential header (us-west-2/dynamodb)", auth)
	}
	// Real creds carry no session token → the placeholder one must be gone.
	if tok := req.Header.Get("X-Amz-Security-Token"); tok != "" {
		t.Errorf("X-Amz-Security-Token = %q, want it stripped", tok)
	}
	// The content hash the agent signed over must be reused verbatim.
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != contentHash {
		t.Errorf("X-Amz-Content-Sha256 = %q, want reused %q", got, contentHash)
	}
}

// TestAWSCredentialReSignFallsBackToHost covers the path where the
// incoming request has no parseable SigV4 credential scope, so service +
// region must be recovered from the hostname.
func TestAWSCredentialReSignFallsBackToHost(t *testing.T) {
	cred := &AWSCredential{}
	req, err := http.NewRequest("GET", "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// No Authorization header → forces the hostname fallback.
	sec := runtime.Secret{Extras: map[string]string{
		"access_key_id":     "AKIDEXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"session_token":     "FwoGZXIvYXdzEXAMPLE",
	}}
	if err := cred.SignHTTPRequest(context.Background(), req, sec, struct{}{}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := req.Header.Get("Authorization")
	// sts.amazonaws.com is a global endpoint → service sts, region us-east-1.
	if !strings.Contains(auth, "/us-east-1/sts/aws4_request") {
		t.Errorf("Authorization = %q, want host-derived scope us-east-1/sts", auth)
	}
	// STS-issued gateway creds carry a session token → signer must stamp it.
	if tok := req.Header.Get("X-Amz-Security-Token"); tok != "FwoGZXIvYXdzEXAMPLE" {
		t.Errorf("X-Amz-Security-Token = %q, want the gateway session token", tok)
	}
}

func TestParseSigV4CredentialScope(t *testing.T) {
	cases := []struct {
		name, header, svc, reg string
	}{
		{"well-formed", "AWS4-HMAC-SHA256 Credential=AKID/20260609/ap-south-1/s3/aws4_request, SignedHeaders=host, Signature=abc", "s3", "ap-south-1"},
		{"missing", "Bearer something", "", ""},
		{"truncated scope", "AWS4-HMAC-SHA256 Credential=AKID/20260609/s3, SignedHeaders=host", "", ""},
		{"not aws4_request", "AWS4-HMAC-SHA256 Credential=AKID/20260609/ap-south-1/s3/v2_request, Signature=abc", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, reg := parseSigV4CredentialScope(tc.header)
			if svc != tc.svc || reg != tc.reg {
				t.Errorf("parseSigV4CredentialScope(%q) = (%q,%q), want (%q,%q)", tc.header, svc, reg, tc.svc, tc.reg)
			}
		})
	}
}

func TestServiceRegionFromHost(t *testing.T) {
	cases := []struct {
		host, svc, reg string
	}{
		{"sts.us-west-2.amazonaws.com", "sts", "us-west-2"},
		{"dynamodb.eu-central-1.amazonaws.com", "dynamodb", "eu-central-1"},
		{"iam.amazonaws.com", "iam", "us-east-1"},
		{"sts.amazonaws.com:443", "sts", "us-east-1"},
		{"not-an-aws-host", "not-an-aws-host", "us-east-1"},
	}
	for _, tc := range cases {
		svc, reg := serviceRegionFromHost(tc.host)
		if svc != tc.svc || reg != tc.reg {
			t.Errorf("serviceRegionFromHost(%q) = (%q,%q), want (%q,%q)", tc.host, svc, reg, tc.svc, tc.reg)
		}
	}
}

// TestAWSCredentialEnvVarsMirrorsAnthropic asserts the aws credential
// auto-injects placeholder env vars the same way anthropic_oauth does.
func TestAWSCredentialEnvVarsMirrorsAnthropic(t *testing.T) {
	got := map[string]string{}
	for _, ev := range (&AWSCredential{}).EnvVars() {
		got[ev.Name] = ev.Value
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"} {
		if got[name] == "" {
			t.Errorf("EnvVars missing %s", name)
		}
	}
	if len(got["AWS_ACCESS_KEY_ID"]) != 20 {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want a 20-char AKIA-shaped placeholder", got["AWS_ACCESS_KEY_ID"])
	}
	if len(got["AWS_SECRET_ACCESS_KEY"]) != 40 {
		t.Errorf("AWS_SECRET_ACCESS_KEY = %q, want a 40-char placeholder", got["AWS_SECRET_ACCESS_KEY"])
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
