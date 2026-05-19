package main

import (
	"net/http"
	"testing"
)

func TestFlatHeadersRedactsSensitiveHeaders(t *testing.T) {
	headers := http.Header{
		"Authorization":  []string{"Bearer real-token"},
		"Cookie":         []string{"session=secret"},
		"X-Api-Key":      []string{"abc123"},
		"X-Secret-Token": []string{"secret-token"},
		"User-Agent":     []string{"clawpatrol-test"},
		"Accept":         []string{"application/json"},
	}

	got := flatHeaders(headers)

	for _, key := range []string{"Authorization", "Cookie", "X-Api-Key", "X-Secret-Token"} {
		if got[key] != "***" {
			t.Fatalf("%s = %q, want redacted", key, got[key])
		}
	}
	if got["User-Agent"] != "clawpatrol-test" {
		t.Fatalf("User-Agent = %q, want original value", got["User-Agent"])
	}
	if got["Accept"] != "application/json" {
		t.Fatalf("Accept = %q, want original value", got["Accept"])
	}
}

func TestFlatHeadersRedactionIsCaseInsensitive(t *testing.T) {
	headers := http.Header{
		"x-auth-token": []string{"lowercase-secret"},
		"X-PASSWORD":   []string{"uppercase-secret"},
	}

	got := flatHeaders(headers)

	if got["x-auth-token"] != "***" {
		t.Fatalf("x-auth-token = %q, want redacted", got["x-auth-token"])
	}
	if got["X-PASSWORD"] != "***" {
		t.Fatalf("X-PASSWORD = %q, want redacted", got["X-PASSWORD"])
	}
}
