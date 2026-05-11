package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config/plugins/credentials"
	"github.com/denoland/clawpatrol/config/runtime"
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

func TestBodySampleRedactorRedactsCredentialBytes(t *testing.T) {
	const credentialValue = "123456789:REAL_SECRET_TOKEN"
	sample := `{"url":"https://example.com/bot` + credentialValue + `/hook"}`

	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Bytes: []byte(credentialValue)})
	got := redactor.Redact(sample)

	if strings.Contains(got, credentialValue) || strings.Contains(got, "REAL_SECRET_TOKEN") {
		t.Fatalf("redacted sample still contains credential: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("redacted sample = %q, want redaction marker", got)
	}
}

func TestBodySampleRedactorRedactsTelegramPostInjectionBodySample(t *testing.T) {
	const placeholder = "0000000000:clawpatrol-placeholder-do-not-use"
	const credentialValue = "123456789:REAL_SECRET_TOKEN"
	body := `{"url":"https://example.com/bot` + placeholder + `/hook"}`
	req, err := http.NewRequest("POST", "https://api.telegram.org/bot"+placeholder+"/setWebhook", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	redactor := newBodySampleRedactor()
	sec := runtime.Secret{Bytes: []byte(credentialValue)}
	redactor.AddSecret(sec)
	if err := (&credentials.TelegramBotToken{}).InjectHTTP(req.Context(), req, sec); err != nil {
		t.Fatalf("inject telegram credential: %v", err)
	}
	reqS := newSampler(4096)
	req.Body = wrapBodySampler(req.Body, reqS)
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatalf("read sampled request body: %v", err)
	}

	got := redactor.RedactSample(reqS)
	if strings.Contains(got, credentialValue) || strings.Contains(got, "REAL_SECRET_TOKEN") {
		t.Fatalf("redacted post-injection sample still contains credential: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("redacted post-injection sample = %q, want redaction marker", got)
	}
}

func TestBodySampleRedactorRedactsConfiguredSecretFromHeaderValues(t *testing.T) {
	const credentialValue = "header-value-that-must-not-leak"
	req, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept", "application/json")

	redactor := newBodySampleRedactor()
	sec := runtime.Secret{Bytes: []byte(credentialValue)}
	redactor.AddSecret(sec)
	if err := (&credentials.HeaderToken{Header: "X-Trace-Context", Prefix: "trace="}).InjectHTTP(req.Context(), req, sec); err != nil {
		t.Fatalf("inject header credential: %v", err)
	}

	got := redactor.RedactHeaderMap(flatHeaders(req.Header))
	if strings.Contains(got["X-Trace-Context"], credentialValue) || strings.Contains(got["X-Trace-Context"], "must-not-leak") {
		t.Fatal("redacted header still contains configured credential")
	}
	if !strings.Contains(got["X-Trace-Context"], "***") {
		t.Fatalf("redacted header = %q, want redaction marker", got["X-Trace-Context"])
	}
	if got["Accept"] != "application/json" {
		t.Fatalf("Accept = %q, want original value", got["Accept"])
	}
}

func TestBodySampleRedactorRedactsTruncatedSamplesWithConfiguredSecrets(t *testing.T) {
	const credentialValue = "boundary-secret-value-that-crosses-sample-cap"
	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Bytes: []byte(credentialValue)})

	s := newSampler(16)
	if _, err := s.Write([]byte(strings.Repeat("a", 14) + credentialValue + "tail")); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	got := redactor.RedactSample(s)
	if got != "***" {
		t.Fatalf("redacted truncated sample = %q, want conservative marker", got)
	}
}

func TestBodySampleRedactorRedactsTruncatedStringSamplesWithConfiguredSecrets(t *testing.T) {
	const credentialValue = "websocket-secret-value-that-crosses-sample-cap"
	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Bytes: []byte(credentialValue)})

	got := redactor.RedactStringSample(strings.Repeat("a", 10)+credentialValue[:4], true)
	if got != "***" {
		t.Fatalf("redacted truncated string sample = %q, want conservative marker", got)
	}
}

func TestBodySampleRedactorRedactsBinarySamplesTruncatedByHexPreview(t *testing.T) {
	secretBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Bytes: secretBytes})

	s := newSampler(128)
	payload := append([]byte{0x00}, bytes.Repeat([]byte{'a'}, binarySamplePreviewBytes-2)...)
	payload = append(payload, secretBytes...)
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	got := redactor.RedactSample(s)
	if got != "***" {
		t.Fatalf("redacted binary preview sample = %q, want conservative marker", got)
	}
}

func TestBodySampleRedactorRedactsOverlappingSecretsLongestFirst(t *testing.T) {
	const shortCredential = "overlap-secret"
	const longCredential = "overlap-secret-with-suffix"
	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Bytes: []byte(shortCredential)})
	redactor.AddSecret(runtime.Secret{Bytes: []byte(longCredential)})

	got := redactor.Redact("value=" + longCredential)
	if strings.Contains(got, "with-suffix") || strings.Contains(got, longCredential) || strings.Contains(got, shortCredential) {
		t.Fatalf("redacted overlapping sample still contains credential material: %q", got)
	}
	if got != "value=***" {
		t.Fatalf("redacted overlapping sample = %q, want full credential replaced once", got)
	}
}

func TestBodySampleRedactorRedactsSecretExtras(t *testing.T) {
	const slackBotCredential = "xoxb-secret-bot-token"
	const slackSigningCredential = "slack-signing-secret"
	sample := "bot=" + slackBotCredential + " signing=" + slackSigningCredential + " public=ok"

	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Extras: map[string]string{
		"bot":            slackBotCredential,
		"signing_secret": slackSigningCredential,
	}})
	got := redactor.Redact(sample)

	for _, credentialValue := range []string{slackBotCredential, slackSigningCredential} {
		if strings.Contains(got, credentialValue) {
			t.Fatalf("redacted sample still contains %q: %q", credentialValue, got)
		}
	}
	if !strings.Contains(got, "public=ok") {
		t.Fatalf("redacted sample lost non-secret text: %q", got)
	}
}

func TestBodySampleRedactorRedactsURLEscapedCredentialBytes(t *testing.T) {
	const credentialValue = "123456789:REAL_SECRET_TOKEN"
	sample := "url=https%3A%2F%2Fexample.com%2Fbot123456789%3AREAL_SECRET_TOKEN%2Fhook"

	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Bytes: []byte(credentialValue)})
	got := redactor.Redact(sample)

	if strings.Contains(got, "123456789%3AREAL_SECRET_TOKEN") || strings.Contains(got, "REAL_SECRET_TOKEN") {
		t.Fatalf("redacted escaped sample still contains credential: %q", got)
	}
}

func TestBodySampleRedactorRedactsBinaryHexSecret(t *testing.T) {
	secretBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	sample := "binary:00" + hex.EncodeToString(secretBytes) + "ff"

	redactor := newBodySampleRedactor()
	redactor.AddSecret(runtime.Secret{Bytes: secretBytes})
	got := redactor.Redact(sample)

	if strings.Contains(got, hex.EncodeToString(secretBytes)) {
		t.Fatalf("redacted binary sample still contains hex credential: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("redacted binary sample = %q, want redaction marker", got)
	}
}

func TestBodySampleRedactorRedactsTelegramTokenPattern(t *testing.T) {
	const credentialValue = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	sample := `{"url":"https://example.com/bot` + credentialValue + `/hook"}`

	got := newBodySampleRedactor().Redact(sample)

	if strings.Contains(got, credentialValue) {
		t.Fatalf("redacted sample still contains Telegram token: %q", got)
	}
	if !strings.Contains(got, "bot***") {
		t.Fatalf("redacted sample = %q, want Telegram token redacted after bot prefix", got)
	}
}
