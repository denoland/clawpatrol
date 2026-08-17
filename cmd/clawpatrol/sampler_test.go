package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

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

type blockingWriteHash struct {
	hash.Hash
	entered chan<- struct{}
	release <-chan struct{}
}

func (h *blockingWriteHash) Write(p []byte) (int, error) {
	close(h.entered)
	<-h.release
	return h.Hash.Write(p)
}

type blockingSumHash struct {
	hash.Hash
	entered chan<- struct{}
	release <-chan struct{}
}

func (h *blockingSumHash) Sum(b []byte) []byte {
	close(h.entered)
	<-h.release
	return h.Hash.Sum(b)
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
	if got := snap.sample; got != "" {
		t.Fatalf("empty body sample = %q, want empty", got)
	}
	if got := snap.captureState(); got != bodyCaptureComplete {
		t.Fatalf("capture state = %q, want %q", got, bodyCaptureComplete)
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
	if got := snap.captureState(); got != bodyCaptureAborted {
		t.Fatalf("capture state = %q, want %q", got, bodyCaptureAborted)
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
	if got := snap.captureState(); got != bodyCaptureAborted {
		t.Fatalf("capture state = %q, want %q", got, bodyCaptureAborted)
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

func TestSamplerIncompleteCappedBodyKeepsStateAndCapMarker(t *testing.T) {
	s := newSampler(2, 10)
	if _, err := s.Write([]byte("partial")); err != nil {
		t.Fatalf("write partial body: %v", err)
	}

	snap := s.snapshot("")
	want := "pa" + bodyTruncatedMarker
	if got := snap.sample; got != want {
		t.Fatalf("sample = %q, want %q", got, want)
	}
	if got := snap.captureState(); got != bodyCaptureIncomplete {
		t.Fatalf("capture state = %q, want %q", got, bodyCaptureIncomplete)
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
	if got := snap.sample; got != string(body[:5])+bodyTruncatedMarker {
		t.Fatalf("sample = %q, want capped prefix plus marker", got)
	}
}

func TestSamplerEarlyResponseSerializesEventSnapshotWithInFlightWrite(t *testing.T) {
	prefix := []byte(`{"prompt":"first half`)
	s := newSampler(4096, int64(len(prefix)+20))
	writeEntered := make(chan struct{})
	releaseWrite := make(chan struct{})
	var releaseWriteOnce sync.Once
	releaseWriter := func() { releaseWriteOnce.Do(func() { close(releaseWrite) }) }
	defer releaseWriter()
	s.hash = &blockingWriteHash{Hash: s.hash, entered: writeEntered, release: releaseWrite}

	snapshotAttempted := make(chan struct{})
	var snapshotAttemptOnce sync.Once
	s.snapshotStartForTest = func() {
		snapshotAttemptOnce.Do(func() { close(snapshotAttempted) })
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := s.Write(prefix)
		writeDone <- err
	}()

	select {
	case <-writeEntered:
	case <-time.After(time.Second):
		t.Fatal("sampler write did not reach the deterministic gate")
	}

	eventDone := make(chan Event, 1)
	go func() {
		snap := s.snapshot("")
		ev := Event{}
		applyRequestBodySnapshot(&ev, snap, nil)
		eventDone <- ev
	}()

	select {
	case <-snapshotAttempted:
	case <-time.After(time.Second):
		t.Fatal("event snapshot did not reach the sampler lock")
	}
	select {
	case <-eventDone:
		t.Fatal("event snapshot completed while sampler Write held the lock")
	default:
	}

	releaseWriter()
	if err := <-writeDone; err != nil {
		t.Fatalf("write prefix: %v", err)
	}
	ev := <-eventDone
	if ev.ReqBody != string(prefix) {
		t.Fatalf("request sample = %q, want %q", ev.ReqBody, prefix)
	}
	if ev.ReqBodyState != bodyCaptureIncomplete {
		t.Fatalf("request capture state = %q, want %q", ev.ReqBodyState, bodyCaptureIncomplete)
	}
	if ev.ReqSha != "" {
		t.Fatalf("early-response SHA = %q, want empty", ev.ReqSha)
	}
}

func TestSamplerSnapshotHoldsLockWhileHashing(t *testing.T) {
	body := []byte("complete body")
	s := newSampler(4096, int64(len(body)))
	if _, err := s.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}

	sumEntered := make(chan struct{})
	releaseSum := make(chan struct{})
	var releaseSumOnce sync.Once
	releaseHasher := func() { releaseSumOnce.Do(func() { close(releaseSum) }) }
	defer releaseHasher()
	s.hash = &blockingSumHash{Hash: s.hash, entered: sumEntered, release: releaseSum}

	snapshotDone := make(chan samplerSnapshot, 1)
	go func() { snapshotDone <- s.snapshot("") }()
	select {
	case <-sumEntered:
	case <-time.After(time.Second):
		t.Fatal("snapshot did not reach the deterministic hash gate")
	}
	if s.mu.TryLock() {
		s.mu.Unlock()
		t.Fatal("snapshot hashed without holding the sampler mutex")
	}

	releaseHasher()
	snap := <-snapshotDone
	if snap.sha != fullBodySHA(body) {
		t.Fatalf("SHA = %q, want %q", snap.sha, fullBodySHA(body))
	}
}

func TestResponseBodyContentLengthUsesHTTPBodySemantics(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		status        int
		contentLength int64
		body          io.ReadCloser
		want          int64
	}{
		{name: "ordinary", method: http.MethodGet, status: http.StatusOK, contentLength: 12, body: http.NoBody, want: 12},
		{name: "head", method: http.MethodHead, status: http.StatusOK, contentLength: 12, body: http.NoBody, want: 0},
		{name: "informational", method: http.MethodGet, status: http.StatusEarlyHints, contentLength: -1, body: http.NoBody, want: 0},
		{name: "no content", method: http.MethodGet, status: http.StatusNoContent, contentLength: -1, body: http.NoBody, want: 0},
		{name: "not modified", method: http.MethodGet, status: http.StatusNotModified, contentLength: 55, body: http.NoBody, want: 0},
		{name: "explicit no body", method: http.MethodGet, status: http.StatusOK, contentLength: -1, body: http.NoBody, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode:    tt.status,
				ContentLength: tt.contentLength,
				Body:          tt.body,
			}
			if got := responseBodyContentLength(tt.method, resp); got != tt.want {
				t.Fatalf("response body content length = %d, want %d", got, tt.want)
			}
		})
	}
}
