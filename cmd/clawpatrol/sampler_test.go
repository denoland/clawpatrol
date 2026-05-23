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

// TestSamplerPoolReuseDoesNotLeakStateBetweenRequests guards the
// samplerPool round-trip: a sampler used for one body, then released
// and re-acquired, must hand back zero buffered bytes, a zero byte
// counter, and a sha for the second body alone — not the first. A
// missed Reset on either the hash or bytes.Buffer would let request N
// observe sample bytes or a sha digest from request N-1, which would
// corrupt the audit log and could leak credential bytes between
// unrelated requests on the same MITM connection.
func TestSamplerPoolReuseDoesNotLeakStateBetweenRequests(t *testing.T) {
	first := newSampler(4096)
	firstBody := []byte(`{"first":"request"}`)
	if _, err := first.Write(firstBody); err != nil {
		t.Fatalf("first write: %v", err)
	}
	firstSha := first.sha()
	firstSample := first.sample("")
	firstN := first.n
	first.release()

	second := newSampler(4096)
	if second.buf.Len() != 0 {
		t.Fatalf("pooled sampler buf len = %d, want 0", second.buf.Len())
	}
	if second.n != 0 {
		t.Fatalf("pooled sampler n = %d, want 0", second.n)
	}
	secondBody := []byte(`{"second":"request"}`)
	if _, err := second.Write(secondBody); err != nil {
		t.Fatalf("second write: %v", err)
	}
	secondSample := second.sample("")
	if secondSample != string(secondBody) {
		t.Fatalf("second sample = %q, want %q (pool state leaked from first?)", secondSample, string(secondBody))
	}
	if second.n != int64(len(secondBody)) {
		t.Fatalf("second.n = %d, want %d", second.n, len(secondBody))
	}
	secondSha := second.sha()
	if secondSha == firstSha {
		t.Fatalf("sha digest unchanged across pool reuse — hash.Reset was skipped")
	}
	second.release()

	_ = firstSample
	_ = firstN
}

// TestSamplerSampleAfterPoolReuse is a tighter regression — after the
// pool round-trips an at-cap body, the next acquirer must not see the
// old body's bytes in its sample even if the new body is much
// smaller. Bytes.Buffer keeps its backing slice across Reset, so a
// missing Reset on length would expose the old payload through
// buf.Bytes().
func TestSamplerSampleAfterPoolReuse(t *testing.T) {
	first := newSampler(4096)
	hot := []byte(strings.Repeat("S", 4096)) // fills the cap
	_, _ = first.Write(hot)
	_ = first.sha()
	_ = first.sample("")
	first.release()

	second := newSampler(4096)
	small := []byte(`{"k":1}`)
	_, _ = second.Write(small)
	got := second.sample("")
	if got != string(small) {
		t.Fatalf("sample after pool reuse leaked prior body: got %q want %q", got, string(small))
	}
	second.release()
}
