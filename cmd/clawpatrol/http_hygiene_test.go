package main

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// roundTripFunc adapts a function to http.RoundTripper so tests can
// substitute an in-process transport for the package-level HTTP
// clients without needing a TCP listener.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// TestOAuthHTTPClientHasTimeout pins the explicit timeout that
// every OAuth-side request inherits. Issue #162 calls out OAuth
// paths as places where http.DefaultClient (no timeout) was used;
// guarding the constant prevents a regression where a future
// refactor drops the bound and lets a stuck IdP hang a refresh
// goroutine indefinitely.
func TestOAuthHTTPClientHasTimeout(t *testing.T) {
	if oauthHTTPClient.Timeout <= 0 {
		t.Fatalf("oauthHTTPClient.Timeout must be > 0, got %v", oauthHTTPClient.Timeout)
	}
	if oauthHTTPTimeout != oauthHTTPClient.Timeout {
		t.Fatalf("oauthHTTPTimeout (%v) and client Timeout (%v) drifted apart",
			oauthHTTPTimeout, oauthHTTPClient.Timeout)
	}
}

// TestTelemetryHTTPClientHasTimeout pins the explicit telemetry
// client's timeout. We send a tiny payload, but a hung
// clawpatrol.dev should never block the long-running goroutine.
func TestTelemetryHTTPClientHasTimeout(t *testing.T) {
	if telemetryHTTPClient.Timeout <= 0 {
		t.Fatalf("telemetryHTTPClient.Timeout must be > 0, got %v",
			telemetryHTTPClient.Timeout)
	}
}

// TestTailscaleAPIClientHasTimeout pins the explicit api.tailscale
// .com client's timeout.
func TestTailscaleAPIClientHasTimeout(t *testing.T) {
	if tailscaleAPIClient.Timeout <= 0 {
		t.Fatalf("tailscaleAPIClient.Timeout must be > 0, got %v",
			tailscaleAPIClient.Timeout)
	}
}

// TestModelRefreshClientHasTimeout pins the litellm refresh
// client's timeout.
func TestModelRefreshClientHasTimeout(t *testing.T) {
	if modelRefreshClient.Timeout <= 0 {
		t.Fatalf("modelRefreshClient.Timeout must be > 0, got %v",
			modelRefreshClient.Timeout)
	}
}

// TestModelDBFetchBoundsRespBody ensures the litellm refresh path
// caps the response body it'll buffer. We hand the client an
// over-cap payload of NUL bytes — json.Decode will fail and the
// LimitReader keeps us from heap-pinning the whole thing first.
func TestModelDBFetchBoundsRespBody(t *testing.T) {
	orig := modelRefreshClient.Transport
	defer func() { modelRefreshClient.Transport = orig }()
	payload := bytes.Repeat([]byte{0}, maxModelDBBody+1<<20)
	var served int64
	modelRefreshClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := &countingReader{r: bytes.NewReader(payload), n: &served}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(body),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	m := &modelDB{byModel: map[string]int64{}}
	if err := m.fetch(); err == nil {
		t.Fatalf("expected JSON decode error for bogus payload, got nil")
	}
	if served > maxModelDBBody+(1<<20) {
		t.Fatalf("limiter let through %d bytes, want <= %d", served, maxModelDBBody+(1<<20))
	}
}

type countingReader struct {
	r io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)
	return n, err
}

// TestBoundedWriterCapsOutput verifies the tee-buffer cap that
// keeps the LLM-tracking tee from growing without bound on a
// large response.
func TestBoundedWriterCapsOutput(t *testing.T) {
	var sink bytes.Buffer
	bw := &boundedWriter{w: &sink, max: 100}
	for _, chunk := range [][]byte{
		bytes.Repeat([]byte("a"), 50),
		bytes.Repeat([]byte("b"), 100),
		bytes.Repeat([]byte("c"), 850),
	} {
		n, err := bw.Write(chunk)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(chunk) {
			t.Fatalf("Write reported short: got %d want %d", n, len(chunk))
		}
	}
	if sink.Len() != 100 {
		t.Fatalf("sink len = %d, want 100 (cap)", sink.Len())
	}
	if !bytes.Equal(sink.Bytes()[:50], bytes.Repeat([]byte("a"), 50)) {
		t.Fatalf("sink prefix wrong: %q", sink.Bytes()[:50])
	}
	if !bytes.Equal(sink.Bytes()[50:], bytes.Repeat([]byte("b"), 50)) {
		t.Fatalf("sink suffix wrong: %q", sink.Bytes()[50:])
	}
}

// TestBoundedWriterAtMax exercises the early-return path where
// the cap is already exhausted before the next Write arrives.
// Important because the path runs once per chunk on long SSE
// streams — a bug here would silently allocate forever.
func TestBoundedWriterAtMax(t *testing.T) {
	var sink bytes.Buffer
	bw := &boundedWriter{w: &sink, max: 10}
	if n, _ := bw.Write(bytes.Repeat([]byte("a"), 10)); n != 10 {
		t.Fatalf("first write n=%d", n)
	}
	// Second write must be a full no-op writer-side but report
	// full length to the surrounding TeeReader.
	if n, _ := bw.Write([]byte("ignored")); n != len("ignored") {
		t.Fatalf("second write must report full length: n=%d", n)
	}
	if sink.Len() != 10 {
		t.Fatalf("sink grew past cap: %d", sink.Len())
	}
}
