package main

import (
	"net/http"
	"strings"
	"testing"
)

// BenchmarkComputeHITLRequestFingerprint covers the per-request HMAC
// canonicalization. Runs on every HITL-eligible request and again on
// every retry-grant relay, so allocation count matters.
func BenchmarkComputeHITLRequestFingerprint(b *testing.B) {
	body := []byte(`{"input":"hello","arr":[1,2,3,4,5,6,7,8,9,10]}`)
	in := HITLRequestFingerprintInput{
		Key: HITLFingerprintKey{
			ID:   "k1",
			Root: []byte(strings.Repeat("k", 32)),
		},
		ProfileID:      "default",
		PrincipalID:    "tail-abc",
		EndpointID:     "api",
		ApprovalRuleID: "rule-1",
		Method:         http.MethodPost,
		Scheme:         "https",
		Host:           "api.example.com",
		Path:           "/v1/things",
		RawQuery:       "q=1&debug=true",
		SelectedHeaders: []HITLFingerprintHeader{
			{Name: "content-type", Values: []string{"application/json"}},
			{Name: "x-resource", Values: []string{"customers/42"}},
		},
		RawBody:       body,
		AuthBindingID: "credential:v1:placeholder",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ComputeHITLRequestFingerprint(in); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSelectHITLFingerprintHeaders covers the per-request
// header allowlist filtering invoked when async HITL operations
// fingerprint a request's selected headers.
func BenchmarkSelectHITLFingerprintHeaders(b *testing.B) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Resource", "customers/42")
	h.Set("X-Trace-Id", "deadbeef")
	h.Set("X-Tenant", "acme")
	h.Set("User-Agent", "agent/1.0")
	allow := []string{"content-type", "x-resource", "x-tenant"}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := SelectHITLFingerprintHeaders(h, allow); err != nil {
			b.Fatal(err)
		}
	}
}
