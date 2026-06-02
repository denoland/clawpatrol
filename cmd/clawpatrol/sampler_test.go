package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func brotlied(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write([]byte(s)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

func zlibbed(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func rawDeflated(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := fw.Write([]byte(s)); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func zstdded(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

func TestSamplerSampleGzip(t *testing.T) {
	want := `{"hello":"world","arr":[1,2,3]}`
	s := newSampler(4096)
	_, _ = s.Write(gzipped(t, want))
	got := s.sample("gzip")
	if got != want {
		t.Fatalf("gzip sample\n  want %q\n   got %q", want, got)
	}
}

func TestSamplerSampleBrotli(t *testing.T) {
	want := `{"hello":"world","arr":[1,2,3]}`
	s := newSampler(4096)
	_, _ = s.Write(brotlied(t, want))
	got := s.sample("br")
	if got != want {
		t.Fatalf("br sample\n  want %q\n   got %q", want, got)
	}
}

func TestSamplerSampleDeflateZlib(t *testing.T) {
	want := `{"hello":"world"}`
	s := newSampler(4096)
	_, _ = s.Write(zlibbed(t, want))
	got := s.sample("deflate")
	if got != want {
		t.Fatalf("zlib-deflate sample\n  want %q\n   got %q", want, got)
	}
}

func TestSamplerSampleDeflateRaw(t *testing.T) {
	// Some servers send raw deflate under "Content-Encoding: deflate"
	// despite the RFC requiring zlib framing.
	want := `{"hello":"world"}`
	s := newSampler(4096)
	_, _ = s.Write(rawDeflated(t, want))
	got := s.sample("deflate")
	if got != want {
		t.Fatalf("raw-deflate sample\n  want %q\n   got %q", want, got)
	}
}

func TestSamplerSampleZstd(t *testing.T) {
	want := `{"hello":"world","arr":[1,2,3]}`
	s := newSampler(4096)
	_, _ = s.Write(zstdded(t, want))
	got := s.sample("zstd")
	if got != want {
		t.Fatalf("zstd sample\n  want %q\n   got %q", want, got)
	}
}

func TestMaybeDecodeCapsExpandedGzip(t *testing.T) {
	const capBytes = 4096
	const truncatedMarker = "\n[decoded response sample truncated]"

	plain := strings.Repeat("a", capBytes*4)
	compressed := gzipped(t, plain)
	if len(compressed) >= capBytes {
		t.Fatalf("test gzip payload should fit compressed sampler cap: %d >= %d", len(compressed), capBytes)
	}

	got := maybeDecode(compressed, "gzip")
	if len(got) > capBytes+len(truncatedMarker) {
		t.Fatalf("decoded gzip sample length = %d, want <= %d", len(got), capBytes+len(truncatedMarker))
	}
	if !bytes.HasSuffix(got, []byte(truncatedMarker)) {
		t.Fatalf("decoded gzip sample should end with truncation marker %q; got suffix %q", truncatedMarker, string(got[max(0, len(got)-len(truncatedMarker)):]))
	}
	if gotPrefix := string(got[:capBytes]); gotPrefix != plain[:capBytes] {
		t.Fatalf("decoded gzip prefix was not preserved")
	}
}

func TestSamplerSamplePlaintext(t *testing.T) {
	s := newSampler(4096)
	_, _ = s.Write([]byte(`{"hello":"world"}`))
	if got := s.sample(""); got != `{"hello":"world"}` {
		t.Fatalf("plaintext sample: %q", got)
	}
}

func TestSamplerSampleBinaryFallback(t *testing.T) {
	// Raw binary bytes with no encoding header — should hex-prefix.
	s := newSampler(4096)
	_, _ = s.Write([]byte{0x00, 0xff, 0x01, 0xfe})
	got := s.sample("")
	if !strings.HasPrefix(got, "binary:") {
		t.Fatalf("expected binary: prefix, got %q", got)
	}
}

func TestSamplerSampleUnknownEncodingIgnored(t *testing.T) {
	// Unknown encoding falls through to the printable check on raw bytes.
	s := newSampler(4096)
	_, _ = s.Write([]byte{0x1f, 0x8b, 0x08, 0x00})
	got := s.sample("compress")
	if !strings.HasPrefix(got, "binary:") {
		t.Fatalf("expected binary: for unknown encoding, got %q", got)
	}
}

func TestSamplerTruncationMarker(t *testing.T) {
	// Body fits within the cap: no marker, sample is the full body.
	s := newSampler(32)
	body := `{"k":"v"}`
	_, _ = s.Write([]byte(body))
	if got := s.sample(""); got != body {
		t.Fatalf("under-cap sample = %q, want %q (no marker)", got, body)
	}
	if s.truncated() {
		t.Fatalf("under-cap sampler reports truncated")
	}

	// Body exceeds the cap: sample keeps only the prefix and ends with
	// the truncation marker so the dashboard can flag it.
	s = newSampler(8)
	big := strings.Repeat("a", 100)
	_, _ = s.Write([]byte(big))
	if !s.truncated() {
		t.Fatalf("over-cap sampler does not report truncated")
	}
	got := s.sample("")
	if !strings.HasSuffix(got, bodyTruncatedMarker) {
		t.Fatalf("over-cap sample = %q, want suffix %q", got, bodyTruncatedMarker)
	}
	prefix := strings.TrimSuffix(got, bodyTruncatedMarker)
	if prefix != strings.Repeat("a", 8) {
		t.Fatalf("over-cap prefix = %q, want %q", prefix, strings.Repeat("a", 8))
	}
}
