package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type gatedRequestBody struct {
	first          []byte
	rest           []byte
	read           int
	waitingForRest chan struct{}
	releaseRest    chan struct{}
}

func (b *gatedRequestBody) Read(p []byte) (int, error) {
	switch b.read {
	case 0:
		b.read++
		return copy(p, b.first), nil
	case 1:
		b.read++
		close(b.waitingForRest)
		<-b.releaseRest
		return copy(p, b.rest), nil
	default:
		return 0, io.EOF
	}
}

func (*gatedRequestBody) Close() error { return nil }

type earlyResponseRoundTripper struct {
	waitingForBody <-chan struct{}
	bodyReadDone   chan error
}

type dataThenErrorReader struct {
	data []byte
	err  error
}

func (r *dataThenErrorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (*dataThenErrorReader) Close() error { return nil }

func (rt earlyResponseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	go func() {
		_, err := io.Copy(io.Discard, req.Body)
		rt.bodyReadDone <- err
	}()
	<-rt.waitingForBody
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func fullBodySHA(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

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
	s := newSampler(4096, -1)
	_, _ = s.Write(gzipped(t, want))
	got := s.sample("gzip")
	if got != want {
		t.Fatalf("gzip sample\n  want %q\n   got %q", want, got)
	}
}

func TestSamplerSampleBrotli(t *testing.T) {
	want := `{"hello":"world","arr":[1,2,3]}`
	s := newSampler(4096, -1)
	_, _ = s.Write(brotlied(t, want))
	got := s.sample("br")
	if got != want {
		t.Fatalf("br sample\n  want %q\n   got %q", want, got)
	}
}

func TestSamplerSampleDeflateZlib(t *testing.T) {
	want := `{"hello":"world"}`
	s := newSampler(4096, -1)
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
	s := newSampler(4096, -1)
	_, _ = s.Write(rawDeflated(t, want))
	got := s.sample("deflate")
	if got != want {
		t.Fatalf("raw-deflate sample\n  want %q\n   got %q", want, got)
	}
}

func TestSamplerSampleZstd(t *testing.T) {
	want := `{"hello":"world","arr":[1,2,3]}`
	s := newSampler(4096, -1)
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
	s := newSampler(4096, -1)
	_, _ = s.Write([]byte(`{"hello":"world"}`))
	if got := s.sample(""); got != `{"hello":"world"}` {
		t.Fatalf("plaintext sample: %q", got)
	}
}

func TestSamplerSampleBinaryFallback(t *testing.T) {
	// Raw binary bytes with no encoding header — should hex-prefix.
	s := newSampler(4096, -1)
	_, _ = s.Write([]byte{0x00, 0xff, 0x01, 0xfe})
	got := s.sample("")
	if !strings.HasPrefix(got, "binary:") {
		t.Fatalf("expected binary: prefix, got %q", got)
	}
}

func TestSamplerSampleUnknownEncodingIgnored(t *testing.T) {
	// Unknown encoding falls through to the printable check on raw bytes.
	s := newSampler(4096, -1)
	_, _ = s.Write([]byte{0x1f, 0x8b, 0x08, 0x00})
	got := s.sample("compress")
	if !strings.HasPrefix(got, "binary:") {
		t.Fatalf("expected binary: for unknown encoding, got %q", got)
	}
}

func TestSamplerTruncationMarker(t *testing.T) {
	// Body fits within the cap: no marker, sample is the full body.
	s := newSampler(32, -1)
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
	s = newSampler(8, -1)
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

func TestSamplerCompletesAtDeclaredContentLengthWithoutEOF(t *testing.T) {
	body := []byte("complete body")
	s := newSampler(4096, int64(len(body)))
	rc := wrapBodySampler(io.NopCloser(bytes.NewReader(body)), s)

	buf := make([]byte, len(body))
	n, err := rc.Read(buf)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if n != len(body) {
		t.Fatalf("read = %d bytes, want %d", n, len(body))
	}

	snap := s.snapshot("")
	if snap.state != samplerStateComplete {
		t.Fatalf("state = %q, want %q", snap.state, samplerStateComplete)
	}
	if snap.sha != fullBodySHA(body) {
		t.Fatalf("sha = %q, want full-body SHA %q", snap.sha, fullBodySHA(body))
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close complete body: %v", err)
	}
	if state := s.snapshot("").state; state != samplerStateComplete {
		t.Fatalf("state after close = %q, want %q", state, samplerStateComplete)
	}
}

func TestSamplerEmptyBodyIsComplete(t *testing.T) {
	s := newSampler(4096, 0)
	snap := s.snapshot("")
	if snap.state != samplerStateComplete {
		t.Fatalf("state = %q, want %q", snap.state, samplerStateComplete)
	}
	if snap.sha != "" {
		t.Fatalf("empty body SHA = %q, want empty", snap.sha)
	}
	if got := snap.auditSample(); got != "" {
		t.Fatalf("empty body sample = %q, want empty", got)
	}
}

func TestSamplerCompletesUnknownLengthAtEOF(t *testing.T) {
	body := []byte("chunked body")
	s := newSampler(4096, -1)
	rc := wrapBodySampler(io.NopCloser(bytes.NewReader(body)), s)

	if _, err := io.ReadAll(rc); err != nil {
		t.Fatalf("read body: %v", err)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateComplete {
		t.Fatalf("state = %q, want %q", snap.state, samplerStateComplete)
	}
	if snap.sha != fullBodySHA(body) {
		t.Fatalf("sha = %q, want full-body SHA %q", snap.sha, fullBodySHA(body))
	}
}

func TestSamplerShortEOFAbortsDeclaredBody(t *testing.T) {
	body := []byte("short")
	s := newSampler(4096, int64(len(body)+10))
	rc := wrapBodySampler(io.NopCloser(bytes.NewReader(body)), s)

	if _, err := io.ReadAll(rc); err != nil {
		t.Fatalf("read body: %v", err)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateAborted {
		t.Fatalf("state = %q, want %q after short EOF", snap.state, samplerStateAborted)
	}
	if snap.sha != "" {
		t.Fatalf("short body SHA = %q, want empty", snap.sha)
	}
}

func TestSamplerCloseBeforeCompletionIsAborted(t *testing.T) {
	body := []byte("partial")
	s := newSampler(4096, int64(len(body)+10))
	rc := wrapBodySampler(io.NopCloser(bytes.NewReader(body)), s)

	buf := make([]byte, len(body))
	if _, err := rc.Read(buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateAborted {
		t.Fatalf("state = %q, want %q", snap.state, samplerStateAborted)
	}
	if snap.sha != "" {
		t.Fatalf("aborted body SHA = %q, want empty", snap.sha)
	}
	if got := snap.auditSample(); !strings.HasSuffix(got, bodyAbortedMarker) {
		t.Fatalf("aborted sample = %q, want suffix %q", got, bodyAbortedMarker)
	}
}

func TestSamplerReadErrorBeforeCompletionIsAborted(t *testing.T) {
	wantErr := errors.New("request body failed")
	s := newSampler(4096, -1)
	rc := wrapBodySampler(&dataThenErrorReader{data: []byte("partial"), err: wantErr}, s)

	_, err := io.ReadAll(rc)
	if !errors.Is(err, wantErr) {
		t.Fatalf("read error = %v, want %v", err, wantErr)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateAborted {
		t.Fatalf("state = %q, want %q", snap.state, samplerStateAborted)
	}
	if snap.sha != "" {
		t.Fatalf("failed body SHA = %q, want empty", snap.sha)
	}
	if got := snap.auditSample(); !strings.HasSuffix(got, bodyAbortedMarker) {
		t.Fatalf("failed sample = %q, want suffix %q", got, bodyAbortedMarker)
	}
}

func TestSamplerAbortedBodyCannotBecomeComplete(t *testing.T) {
	s := newSampler(4096, 5)
	if _, err := s.Write([]byte("ab")); err != nil {
		t.Fatalf("write prefix: %v", err)
	}
	s.abort()
	if _, err := s.Write([]byte("cde")); err != nil {
		t.Fatalf("write after abort: %v", err)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateAborted {
		t.Fatalf("state = %q, want terminal %q", snap.state, samplerStateAborted)
	}
	if snap.sha != "" {
		t.Fatalf("aborted body SHA = %q, want empty", snap.sha)
	}
}

func TestSamplerContentLengthOverrunIsAborted(t *testing.T) {
	body := []byte("too long")
	s := newSampler(4096, int64(len(body)-1))
	if _, err := s.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateAborted {
		t.Fatalf("state = %q, want %q", snap.state, samplerStateAborted)
	}
	if snap.sha != "" {
		t.Fatalf("overrun body SHA = %q, want empty", snap.sha)
	}
}

func TestSamplerWriteAfterCompleteInvalidatesDigest(t *testing.T) {
	s := newSampler(4096, 3)
	if _, err := s.Write([]byte("one")); err != nil {
		t.Fatalf("write declared body: %v", err)
	}
	if state := s.snapshot("").state; state != samplerStateComplete {
		t.Fatalf("state = %q, want %q", state, samplerStateComplete)
	}
	if _, err := s.Write([]byte("extra")); err != nil {
		t.Fatalf("write overrun: %v", err)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateAborted {
		t.Fatalf("state after overrun = %q, want %q", snap.state, samplerStateAborted)
	}
	if snap.sha != "" {
		t.Fatalf("overrun body SHA = %q, want empty", snap.sha)
	}
}

func TestSamplerIncompleteCappedBodyKeepsBothMarkers(t *testing.T) {
	s := newSampler(2, 10)
	if _, err := s.Write([]byte("partial")); err != nil {
		t.Fatalf("write partial body: %v", err)
	}

	snap := s.snapshot("")
	want := "pa" + bodyIncompleteMarker + bodyTruncatedMarker
	if got := snap.auditSample(); got != want {
		t.Fatalf("sample = %q, want %q", got, want)
	}
	if snap.sha != "" {
		t.Fatalf("incomplete body SHA = %q, want empty", snap.sha)
	}
}

func TestSamplerCappedCompleteBodyKeepsFullSHA(t *testing.T) {
	body := []byte("whole body larger than cap")
	s := newSampler(5, int64(len(body)))
	rc := wrapBodySampler(io.NopCloser(bytes.NewReader(body)), s)

	if _, err := io.ReadAll(rc); err != nil {
		t.Fatalf("read body: %v", err)
	}

	snap := s.snapshot("")
	if snap.state != samplerStateComplete {
		t.Fatalf("state = %q, want %q", snap.state, samplerStateComplete)
	}
	if snap.sha != fullBodySHA(body) {
		t.Fatalf("sha = %q, want full-body SHA %q", snap.sha, fullBodySHA(body))
	}
	if got := snap.auditSample(); got != string(body[:5])+bodyTruncatedMarker {
		t.Fatalf("sample = %q, want capped prefix plus marker", got)
	}
}

func TestSamplerEarlyResponseDoesNotEmitPartialSHA(t *testing.T) {
	first := []byte(`{"prompt":"first half`)
	rest := []byte(` and second half"}`)
	whole := append(append([]byte(nil), first...), rest...)
	body := &gatedRequestBody{
		first:          first,
		rest:           rest,
		waitingForRest: make(chan struct{}),
		releaseRest:    make(chan struct{}),
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.example/v1/messages", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.ContentLength = int64(len(whole))
	s := newSampler(4096, req.ContentLength)
	req.Body = wrapBodySampler(req.Body, s)
	bodyReadDone := make(chan error, 1)
	rt := earlyResponseRoundTripper{
		waitingForBody: body.waitingForRest,
		bodyReadDone:   bodyReadDone,
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	partial := s.snapshot("")
	if partial.state != samplerStatePending {
		t.Fatalf("early-response state = %q, want %q", partial.state, samplerStatePending)
	}
	if partial.sha != "" {
		t.Fatalf("early-response SHA = %q, want empty (partial body)", partial.sha)
	}
	if got := partial.auditSample(); !strings.HasSuffix(got, bodyIncompleteMarker) {
		t.Fatalf("early-response sample = %q, want suffix %q", got, bodyIncompleteMarker)
	}

	close(body.releaseRest)
	if err := <-bodyReadDone; err != nil {
		t.Fatalf("finish reading body: %v", err)
	}

	complete := s.snapshot("")
	if complete.state != samplerStateComplete {
		t.Fatalf("finished state = %q, want %q", complete.state, samplerStateComplete)
	}
	if complete.sha != fullBodySHA(whole) {
		t.Fatalf("finished SHA = %q, want full-body SHA %q", complete.sha, fullBodySHA(whole))
	}
	if got := complete.auditSample(); got != string(whole) {
		t.Fatalf("finished sample = %q, want %q", got, whole)
	}
}
