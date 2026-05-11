package main

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config/runtime"
)

func TestRedactSecretSampleRedactsBytesAndExtras(t *testing.T) {
	sec := runtime.Secret{
		Bytes:  []byte("123456789:REAL_TELEGRAM_TOKEN"),
		Extras: map[string]string{"bot_token": "extra-secret-value"},
	}

	got := redactSecretSample(`{"url":"https://example.com/bot123456789:REAL_TELEGRAM_TOKEN/hook","other":"extra-secret-value"}`, []runtime.Secret{sec})
	if strings.Contains(got, "REAL_TELEGRAM_TOKEN") || strings.Contains(got, "extra-secret-value") {
		t.Fatalf("sample still contains secret material: %s", got)
	}
	if got == "" || got == "***" {
		t.Fatalf("sample = %q, want redacted sample preserving context", got)
	}
}

func TestRedactSecretSampleRedactsHexEncodedBinarySecrets(t *testing.T) {
	sec := runtime.Secret{Bytes: []byte("binary-secret-value")}
	hexSecret := hex.EncodeToString(sec.Bytes)

	got := redactSecretSample("binary:0000"+hexSecret+"ffff", []runtime.Secret{sec})
	if strings.Contains(got, hexSecret) || strings.Contains(got, "binary-secret-value") {
		t.Fatalf("sample still contains secret material: %s", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("sample = %q, want redaction marker", got)
	}
}

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
