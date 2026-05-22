package main

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func gzipBytes(b *testing.B, s string) []byte {
	b.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		b.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		b.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func BenchmarkMaybeDecodeGzip(b *testing.B) {
	payload := gzipBytes(b, strings.Repeat(`{"k":"v"}`, 256))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = maybeDecode(payload, "gzip")
	}
}

func BenchmarkMaybeDecodeUnknown(b *testing.B) {
	payload := []byte(strings.Repeat("plain bytes ", 200))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = maybeDecode(payload, "compress")
	}
}

// BenchmarkSamplerWriteSample mirrors the per-request gateway path:
// stream a body through the sampler, then call sample() to render the
// audit-log preview.
func BenchmarkSamplerWriteSample(b *testing.B) {
	body := []byte(strings.Repeat(`{"hello":"world"}`, 200))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := newSampler(4096)
		_, _ = s.Write(body)
		_ = s.sample("")
	}
}
