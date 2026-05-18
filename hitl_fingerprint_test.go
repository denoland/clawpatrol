package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestHITLRequestFingerprintUsesRawBodyHMACAndDomainSeparatedRequestHMAC(t *testing.T) {
	key := HITLFingerprintKey{
		ID:   "hitl-hmac:v1",
		Root: []byte("test root key used only for deterministic HMAC tests"),
	}
	input := HITLRequestFingerprintInput{
		Key:            key,
		ProfileID:      "agent",
		PrincipalID:    "peer:100.64.0.10",
		EndpointID:     "dangerous-api",
		ApprovalRuleID: "approved-post",
		Method:         "post",
		Scheme:         "HTTPS",
		Host:           "API.EXAMPLE.TEST:8443",
		Path:           "/v1/resources/../resources/%32",
		RawQuery:       "b=two&a=one&a=again",
		SelectedHeaders: []HITLFingerprintHeader{
			{Name: "Content-Type", Values: []string{" application/json "}},
			{Name: "If-Match", Values: []string{" \"rev-1\" "}},
		},
		RawBody:       []byte(`{"resource":"demo","approved":true}`),
		AuthBindingID: "credential:v1:test-binding",
	}

	got, err := ComputeHITLRequestFingerprint(input)
	if err != nil {
		t.Fatalf("ComputeHITLRequestFingerprint err = %v", err)
	}

	bodyKey := testHITLHMAC(key.Root, "clawpatrol hitl body fingerprint v1", nil)
	wantBodyHMAC := "hmac-sha256:" + hex.EncodeToString(testHITLHMAC(bodyKey, "", input.RawBody))
	if got.BodyHMAC != wantBodyHMAC {
		t.Fatalf("BodyHMAC = %q, want %q", got.BodyHMAC, wantBodyHMAC)
	}

	canonical := testCanonicalHITLRequest(input, wantBodyHMAC)
	requestKey := testHITLHMAC(key.Root, "clawpatrol hitl request fingerprint v1", nil)
	wantRequest := "hmac-sha256:" + hex.EncodeToString(testHITLHMAC(requestKey, "", canonical))
	if got.RequestFingerprint != wantRequest {
		t.Fatalf("RequestFingerprint = %q, want %q", got.RequestFingerprint, wantRequest)
	}
	if got.Version != HITLFingerprintVersionV1 {
		t.Fatalf("Version = %q, want %q", got.Version, HITLFingerprintVersionV1)
	}
	if got.HMACKeyID != key.ID {
		t.Fatalf("HMACKeyID = %q, want %q", got.HMACKeyID, key.ID)
	}
	for _, out := range []string{got.BodyHMAC, got.RequestFingerprint} {
		if strings.Contains(out, string(key.Root)) || strings.Contains(out, string(input.RawBody)) {
			t.Fatalf("fingerprint output leaked secret or raw body material: %q", out)
		}
	}
}

func TestHITLRequestFingerprintCanonicalizationIsStrictAndRaw(t *testing.T) {
	base := testHITLFingerprintInput()
	baseResult := mustComputeHITLFingerprint(t, base)

	caseFolded := base
	caseFolded.Method = "POST"
	caseFolded.Scheme = "https"
	caseFolded.Host = "api.example.test"
	if got := mustComputeHITLFingerprint(t, caseFolded); got.RequestFingerprint != baseResult.RequestFingerprint {
		t.Fatalf("method/scheme/host canonicalization changed fingerprint: %q vs %q", got.RequestFingerprint, baseResult.RequestFingerprint)
	}

	changedPath := base
	changedPath.Path = "/v1/resources/2"
	if got := mustComputeHITLFingerprint(t, changedPath); got.RequestFingerprint == baseResult.RequestFingerprint {
		t.Fatal("path normalization must not hide byte-level path changes")
	}

	changedQueryOrder := base
	changedQueryOrder.RawQuery = "a=one&b=two"
	if got := mustComputeHITLFingerprint(t, changedQueryOrder); got.RequestFingerprint == baseResult.RequestFingerprint {
		t.Fatal("raw query sorting/normalization must not hide query byte-order changes")
	}

	changedHeaderOrder := base
	changedHeaderOrder.SelectedHeaders = []HITLFingerprintHeader{
		{Name: "If-Match", Values: []string{"rev-1"}},
		{Name: "Content-Type", Values: []string{"application/json"}},
	}
	if got := mustComputeHITLFingerprint(t, changedHeaderOrder); got.RequestFingerprint == baseResult.RequestFingerprint {
		t.Fatal("selected header order must remain part of canonical request bytes")
	}

	changedBodyWhitespace := base
	changedBodyWhitespace.RawBody = append([]byte(nil), base.RawBody...)
	changedBodyWhitespace.RawBody = append(changedBodyWhitespace.RawBody, '\n')
	if got := mustComputeHITLFingerprint(t, changedBodyWhitespace); got.RequestFingerprint == baseResult.RequestFingerprint || got.BodyHMAC == baseResult.BodyHMAC {
		t.Fatal("raw body HMAC must change when exact body bytes change")
	}
}

func TestSelectHITLFingerprintHeadersUsesAllowlistOrderAndRejectsAuthHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Add("Content-Type", " application/json ")
	headers.Add("If-Match", " \"rev-1\" ")
	headers.Add("X-Request-Id", "trace-me")
	headers.Add("Authorization", "Bearer must-not-enter-fingerprint")
	headers.Add("Cookie", "session=must-not-enter-fingerprint")

	selected, err := SelectHITLFingerprintHeaders(headers, []string{"If-Match", "Content-Type"})
	if err != nil {
		t.Fatalf("SelectHITLFingerprintHeaders err = %v", err)
	}
	want := []HITLFingerprintHeader{
		{Name: "if-match", Values: []string{"\"rev-1\""}},
		{Name: "content-type", Values: []string{"application/json"}},
	}
	if !equalHITLHeaders(selected, want) {
		t.Fatalf("selected headers = %#v, want %#v", selected, want)
	}
	for _, h := range selected {
		if h.Name == "authorization" || h.Name == "cookie" || strings.Contains(strings.Join(h.Values, ","), "must-not-enter") {
			t.Fatalf("selected auth-bearing header material: %#v", selected)
		}
	}

	for _, forbidden := range []string{
		"Authorization",
		"Cookie",
		"Proxy-Authorization",
		"Connection",
		"Transfer-Encoding",
		"X-Request-Id",
		"Traceparent",
		"X-API-Key",
		"API-Key",
		"X-Auth-Token",
		"X-Authorization",
		"X-Secret",
		"Idempotency-Key",
	} {
		if _, err := SelectHITLFingerprintHeaders(headers, []string{forbidden}); err == nil {
			t.Fatalf("SelectHITLFingerprintHeaders(%q) err = nil, want rejection", forbidden)
		}
	}
}

func TestHITLCredentialAuthBindingIDUsesNonSecretIdentityAndGeneration(t *testing.T) {
	binding, err := BuildHITLCredentialAuthBindingID(HITLCredentialAuthBindingInput{
		ProfileID:    "agent",
		CredentialID: "deploy-api",
		Generation:   "generation-1",
		SubjectID:    "tenant-42",
	})
	if err != nil {
		t.Fatalf("BuildHITLCredentialAuthBindingID err = %v", err)
	}
	if !strings.HasPrefix(binding, "credential:v1:") {
		t.Fatalf("binding = %q, want credential:v1 prefix", binding)
	}
	if strings.Contains(binding, "agent") || strings.Contains(binding, "deploy-api") || strings.Contains(binding, "generation-1") || strings.Contains(binding, "tenant-42") {
		t.Fatalf("binding should be an opaque non-secret identifier, got %q", binding)
	}

	same, err := BuildHITLCredentialAuthBindingID(HITLCredentialAuthBindingInput{
		ProfileID:    "agent",
		CredentialID: "deploy-api",
		Generation:   "generation-1",
		SubjectID:    "tenant-42",
	})
	if err != nil {
		t.Fatalf("same binding err = %v", err)
	}
	if same != binding {
		t.Fatalf("binding not stable: %q vs %q", same, binding)
	}

	rotated, err := BuildHITLCredentialAuthBindingID(HITLCredentialAuthBindingInput{
		ProfileID:    "agent",
		CredentialID: "deploy-api",
		Generation:   "generation-2",
		SubjectID:    "tenant-42",
	})
	if err != nil {
		t.Fatalf("rotated binding err = %v", err)
	}
	if rotated == binding {
		t.Fatal("credential generation change must change auth binding id")
	}

	if _, err := BuildHITLCredentialAuthBindingID(HITLCredentialAuthBindingInput{ProfileID: "agent", CredentialID: "deploy-api"}); err == nil {
		t.Fatal("missing generation err = nil, want invalid input")
	}
}

func testHITLFingerprintInput() HITLRequestFingerprintInput {
	return HITLRequestFingerprintInput{
		Key: HITLFingerprintKey{
			ID:   "hitl-hmac:v1",
			Root: []byte("test root key used only for deterministic HMAC tests"),
		},
		ProfileID:      "agent",
		PrincipalID:    "peer:100.64.0.10",
		EndpointID:     "dangerous-api",
		ApprovalRuleID: "approved-post",
		Method:         "post",
		Scheme:         "HTTPS",
		Host:           "API.EXAMPLE.TEST",
		Path:           "/v1/resources/%32",
		RawQuery:       "b=two&a=one",
		SelectedHeaders: []HITLFingerprintHeader{
			{Name: "Content-Type", Values: []string{" application/json "}},
			{Name: "If-Match", Values: []string{" rev-1 "}},
		},
		RawBody:       []byte(`{"resource":"demo","approved":true}`),
		AuthBindingID: "credential:v1:test-binding",
	}
}

func mustComputeHITLFingerprint(t *testing.T, in HITLRequestFingerprintInput) HITLRequestFingerprintResult {
	t.Helper()
	got, err := ComputeHITLRequestFingerprint(in)
	if err != nil {
		t.Fatalf("ComputeHITLRequestFingerprint err = %v", err)
	}
	return got
}

func testHITLHMAC(key []byte, domain string, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	if domain != "" {
		_, _ = mac.Write([]byte(domain))
	}
	if msg != nil {
		_, _ = mac.Write(msg)
	}
	return mac.Sum(nil)
}

func testCanonicalHITLRequest(in HITLRequestFingerprintInput, bodyHMAC string) []byte {
	var b bytes.Buffer
	testWriteCanonicalField(&b, "fingerprint_version", HITLFingerprintVersionV1)
	testWriteCanonicalField(&b, "profile_id", in.ProfileID)
	testWriteCanonicalField(&b, "principal_id", in.PrincipalID)
	testWriteCanonicalField(&b, "endpoint_id", in.EndpointID)
	testWriteCanonicalField(&b, "approval_rule_id", in.ApprovalRuleID)
	testWriteCanonicalField(&b, "method", strings.ToUpper(in.Method))
	testWriteCanonicalField(&b, "scheme", strings.ToLower(in.Scheme))
	testWriteCanonicalField(&b, "host", strings.ToLower(in.Host))
	testWriteCanonicalField(&b, "path", in.Path)
	testWriteCanonicalField(&b, "raw_query", in.RawQuery)
	testWriteCanonicalField(&b, "selected_header_count", strconv.Itoa(len(in.SelectedHeaders)))
	for _, h := range in.SelectedHeaders {
		testWriteCanonicalField(&b, "selected_header_name", strings.ToLower(h.Name))
		testWriteCanonicalField(&b, "selected_header_value_count", strconv.Itoa(len(h.Values)))
		for _, v := range h.Values {
			testWriteCanonicalField(&b, "selected_header_value", strings.TrimSpace(v))
		}
	}
	testWriteCanonicalField(&b, "body_hmac", bodyHMAC)
	testWriteCanonicalField(&b, "auth_binding_id", in.AuthBindingID)
	return b.Bytes()
}

func testWriteCanonicalField(b *bytes.Buffer, name, value string) {
	b.WriteString(strconv.Itoa(len(name)))
	b.WriteByte(':')
	b.WriteString(name)
	b.WriteByte('=')
	b.WriteString(strconv.Itoa(len(value)))
	b.WriteByte(':')
	b.WriteString(value)
	b.WriteByte('\n')
}

func equalHITLHeaders(a, b []HITLFingerprintHeader) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || len(a[i].Values) != len(b[i].Values) {
			return false
		}
		for j := range a[i].Values {
			if a[i].Values[j] != b[i].Values[j] {
				return false
			}
		}
	}
	return true
}
