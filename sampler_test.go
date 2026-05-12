package main

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
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

func TestSamplerSampleGzip(t *testing.T) {
	want := `{"hello":"world","arr":[1,2,3]}`
	s := newSampler(4096)
	_, _ = s.Write(gzipped(t, want))
	got := s.sample("gzip")
	if got != want {
		t.Fatalf("gzip sample\n  want %q\n   got %q", want, got)
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

func TestSamplerSampleNonGzipEncodingIgnored(t *testing.T) {
	// br/deflate aren't decoded yet; falling through to printable
	// check on the raw bytes is the documented behaviour.
	s := newSampler(4096)
	_, _ = s.Write([]byte{0x1f, 0x8b, 0x08, 0x00}) // gzip-magic but unknown encoding
	got := s.sample("br")
	if !strings.HasPrefix(got, "binary:") {
		t.Fatalf("expected binary: for unknown encoding, got %q", got)
	}
}
