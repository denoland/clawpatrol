package main

import (
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Benchmarks for the gateway hot paths called on every MITM HTTP
// request: response sanitization, header flattening for the audit
// log, and credential-secret redaction over a sampled body. These
// run unconditionally per request, so even small per-call wins
// compound under load.

func benchFlatHeadersFixture() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", "1234")
	h.Set("Server", "nginx")
	h.Set("Date", "Mon, 01 Jan 2026 00:00:00 GMT")
	h.Set("Cache-Control", "no-store")
	h.Set("Authorization", "Bearer abcdef")
	h.Set("Cookie", "session=xyz")
	h.Add("Set-Cookie", "x=1")
	h.Add("Set-Cookie", "y=2")
	h.Set("X-Request-Id", "deadbeef")
	h.Set("X-Forwarded-For", "10.0.0.1")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	return h
}

func BenchmarkFlatHeaders(b *testing.B) {
	h := benchFlatHeadersFixture()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = flatHeaders(h)
	}
}

func benchStripFixture() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Server", "envoy")
	h.Add("Set-Cookie", "session=abc")
	h.Add("Set-Cookie", "refresh=def")
	h.Set("Set-Cookie2", "legacy=ghi")
	h.Set("WWW-Authenticate", `Bearer realm="x"`)
	h.Set("Proxy-Authenticate", `Basic realm="x"`)
	h.Set("Authentication-Info", `nextnonce="x"`)
	h.Set("Proxy-Authentication-Info", `rspauth="x"`)
	h.Set("X-Custom", "keep")
	h.Set("Date", "Mon, 01 Jan 2026 00:00:00 GMT")
	return h
}

func BenchmarkStripAuthResponseHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := benchStripFixture()
		stripAuthResponseHeaders(h)
	}
}

func BenchmarkStripAuthResponseHeadersRaw(b *testing.B) {
	in := []byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: abc\r\n" +
		"set-cookie: session=abc\r\n" +
		"Set-Cookie: refresh=def\r\n" +
		"WWW-Authenticate: Bearer realm=\"x\"\r\n" +
		"X-Custom: keep\r\n" +
		"Server: envoy\r\n" +
		"\r\n")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = stripAuthResponseHeadersRaw(in)
	}
}

// BenchmarkRedactCredentialSampleSingleSecret models the typical
// MITM path: one credential bound, one Bearer token to scrub from
// the sampled body. A single full-string scan dominates.
func BenchmarkRedactCredentialSampleSingleSecret(b *testing.B) {
	sample := `{"input":"hello","auth":"Bearer sk-test-1234567890","other":"plain"}`
	secrets := []string{"sk-test-1234567890"}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = redactCredentialSample(sample, secrets)
	}
}

// BenchmarkRedactCredentialSampleMultiSecret models the worst case:
// a credential whose Secret.Extras carries several slot values, all
// of which must be scrubbed from the sample. Each adds another
// full-string scan in the old implementation.
func BenchmarkRedactCredentialSampleMultiSecret(b *testing.B) {
	sample := `{"primary":"Bearer sk-test-PRIMARY-KEY","backup":"sk-backup-KEY","tenant":"acct-AAA","client":"id-BBB","tag":"OPSEC"}`
	secrets := []string{
		"sk-test-PRIMARY-KEY",
		"sk-backup-KEY",
		"acct-AAA",
		"id-BBB",
		"OPSEC",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = redactCredentialSample(sample, secrets)
	}
}

// BenchmarkAppendCredentialSecretRedactions covers the per-request
// dedup that builds the redaction list before sample scrubbing.
func BenchmarkAppendCredentialSecretRedactions(b *testing.B) {
	sec := runtime.Secret{
		Bytes: []byte("sk-test-primary"),
		Extras: map[string]string{
			"refresh": "rt-XYZ-12345",
			"account": "acct-AAA",
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = appendCredentialSecretRedactions(nil, sec)
	}
}
