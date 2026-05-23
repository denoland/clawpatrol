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
// stream a body through the sampler, render the sha + preview, then
// release back to samplerPool. The release at the bottom matches what
// the MITM relay loop does between keep-alive requests — without it
// the bench would never recycle the pool slot and pay a fresh
// sampler/sha256/buffer allocation per iteration.
func BenchmarkSamplerWriteSample(b *testing.B) {
	body := []byte(strings.Repeat(`{"hello":"world"}`, 200))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := newSampler(4096)
		_, _ = s.Write(body)
		_ = s.sha()
		_ = s.sample("")
		s.release()
	}
}

// BenchmarkSamplerWriteSampleNoRelease shows the worst case for the
// sampler — no release, so samplerPool stays empty and every
// iteration allocates the sampler struct, the sha256 hasher (~200 B),
// and the body buffer. Kept alongside the pooled variant so a
// regression in the relay loop's release path is obvious.
func BenchmarkSamplerWriteSampleNoRelease(b *testing.B) {
	body := []byte(strings.Repeat(`{"hello":"world"}`, 200))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := newSampler(4096)
		_, _ = s.Write(body)
		_ = s.sha()
		_ = s.sample("")
	}
}
