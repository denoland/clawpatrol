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
