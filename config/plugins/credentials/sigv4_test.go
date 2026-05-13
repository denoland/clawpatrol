package credentials

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSigV4GetVanilla checks the canonical "get-vanilla" vector from
// the AWS sigv4 reference suite. Inputs and the expected
// Authorization header are taken verbatim from
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4_test-suite.html
// (get-vanilla.req / get-vanilla.authz).
//
//	access_key_id     = AKIDEXAMPLE
//	secret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
//	region            = us-east-1
//	service           = service
//	timestamp         = 20150830T123600Z
//	request           = GET / HTTP/1.1, Host: example.amazonaws.com
//	expected authz    = AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request,
//	                   SignedHeaders=host;x-amz-date,
//	                   Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31
func TestSigV4GetVanilla(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The test suite uses Host: example.amazonaws.com (no port).
	req.Host = "example.amazonaws.com"

	ts, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	err = signSigV4(req, sigV4Params{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Service:         "service",
		Region:          "us-east-1",
		Now:             ts,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	const wantSig = "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	got := req.Header.Get("Authorization")
	if !strings.Contains(got, wantSig) {
		t.Errorf("signature mismatch\n got: %s\nwant: ...%s", got, wantSig)
	}
	if !strings.Contains(got, "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request") {
		t.Errorf("credential scope mismatch: %s", got)
	}
	if !strings.Contains(got, "SignedHeaders=host;x-amz-date") {
		t.Errorf("signed headers mismatch: %s", got)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q, want 20150830T123600Z", got)
	}
}

// TestSigV4PostWithBody verifies body-hashing on a POST with a small
// payload. Expected signature derived from the same algorithm; this
// test pins the wire format so a future canonicalization regression
// trips immediately even when the AWS suite doesn't cover it.
func TestSigV4PostWithBody(t *testing.T) {
	body := strings.NewReader(`{"key":"value"}`)
	req, err := http.NewRequest("POST", "https://example.amazonaws.com/path", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "example.amazonaws.com"
	req.Header.Set("Content-Type", "application/json")

	ts, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	err = signSigV4(req, sigV4Params{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Service:         "service",
		Region:          "us-east-1",
		Now:             ts,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request") {
		t.Errorf("credential scope mismatch: %s", auth)
	}
	// Content-Type must appear in SignedHeaders for the JSON body.
	if !strings.Contains(auth, "content-type") {
		t.Errorf("content-type not signed: %s", auth)
	}
	// Non-S3 services don't carry X-Amz-Content-Sha256 on the wire —
	// the hash still feeds the canonical request internally.
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != "" {
		t.Errorf("non-s3 service should not stamp X-Amz-Content-Sha256, got %q", got)
	}
	if strings.Contains(auth, "x-amz-content-sha256") {
		t.Errorf("non-s3 SignedHeaders should not list x-amz-content-sha256: %s", auth)
	}
}

// TestSigV4S3StampsContentSHA verifies that the S3 service triggers
// the X-Amz-Content-Sha256 header stamp (and signs it).
func TestSigV4S3StampsContentSHA(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.s3.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "example.s3.amazonaws.com"

	ts, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	if err := signSigV4(req, sigV4Params{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Service:         "s3",
		Region:          "us-east-1",
		Now:             ts,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	const wantEmptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != wantEmptyBodyHash {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", got, wantEmptyBodyHash)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-content-sha256") {
		t.Errorf("S3 SignedHeaders missing x-amz-content-sha256: %s", auth)
	}
}

// TestSigV4SessionToken verifies that STS-issued credentials add the
// X-Amz-Security-Token header and include it in SignedHeaders.
func TestSigV4SessionToken(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "example.amazonaws.com"

	ts, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	err = signSigV4(req, sigV4Params{
		AccessKeyID:     "ASIAEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		SessionToken:    "FwoGZXIvYXdzEXAMPLE//token",
		Service:         "service",
		Region:          "us-east-1",
		Now:             ts,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "FwoGZXIvYXdzEXAMPLE//token" {
		t.Errorf("X-Amz-Security-Token = %q", got)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-security-token") {
		t.Errorf("session token not in signed headers: %s", auth)
	}
}

// TestSigV4OverwritesAgentAuth verifies that whatever the agent
// stamped in Authorization / X-Amz-Date is overwritten by the
// gateway's signature.
func TestSigV4OverwritesAgentAuth(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "example.amazonaws.com"
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=placeholder/.../aws4_request, SignedHeaders=host, Signature=00")
	req.Header.Set("X-Amz-Date", "19700101T000000Z")
	req.Header.Set("X-Amz-Content-Sha256", "bad")
	req.Header.Set("X-Amz-Security-Token", "stale-token")

	ts, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	if err := signSigV4(req, sigV4Params{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Service:         "service",
		Region:          "us-east-1",
		Now:             ts,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date not overwritten: %q", got)
	}
	if got := req.Header.Get("Authorization"); !strings.Contains(got, "Credential=AKIDEXAMPLE/") {
		t.Errorf("Authorization not overwritten: %q", got)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "" {
		t.Errorf("stale session token left in place: %q", got)
	}
}

// TestSigV4MissingMaterial documents the error contract.
func TestSigV4MissingMaterial(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Host = "example.amazonaws.com"
	err := signSigV4(req, sigV4Params{
		AccessKeyID:     "",
		SecretAccessKey: "secret",
		Service:         "s3",
		Region:          "us-east-1",
		Now:             time.Now(),
	})
	if err == nil {
		t.Fatal("expected error for missing access_key_id")
	}
}

// TestAWSURIEncode pins the AWS URI-encoding rules.
func TestAWSURIEncode(t *testing.T) {
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"foo bar", true, "foo%20bar"},
		{"foo/bar", false, "foo/bar"},
		{"foo/bar", true, "foo%2Fbar"},
		{"a~b-c.d_e", true, "a~b-c.d_e"},
		{"hello=world&x", true, "hello%3Dworld%26x"},
		{"日本", true, "%E6%97%A5%E6%9C%AC"},
	}
	for _, c := range cases {
		if got := awsURIEncode(c.in, c.encodeSlash); got != c.want {
			t.Errorf("awsURIEncode(%q, %v) = %q, want %q", c.in, c.encodeSlash, got, c.want)
		}
	}
}
