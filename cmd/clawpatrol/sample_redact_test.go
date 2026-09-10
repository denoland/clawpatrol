package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestInjectedHeaderSecrets(t *testing.T) {
	before := http.Header{"Accept": {"*/*"}, "Authorization": {"Bearer PH_placeholder_1"}}
	after := before.Clone()
	after.Set("Authorization", "Basic dXNlcjpzM2NyZXQtcGFzc3dvcmQ=")
	after.Set("X-Amz-Date", "20260909T000000Z")
	after.Set("X-Short", "abc")
	got := injectedHeaderSecrets(before, after)
	want := map[string]bool{
		"Basic dXNlcjpzM2NyZXQtcGFzc3dvcmQ=": true,
		"dXNlcjpzM2NyZXQtcGFzc3dvcmQ=":       true,
		"20260909T000000Z":                   true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %d values", got, len(want))
	}
	for _, v := range got {
		if !want[v] {
			t.Fatalf("unexpected redaction %q in %q", v, got)
		}
	}
	if s := redactCredentialSample("echo: Authorization: Basic dXNlcjpzM2NyZXQtcGFzc3dvcmQ= ok", got); strings.Contains(s, "dXNlcjpz") {
		t.Fatalf("derived credential survived redaction: %q", s)
	}
}
