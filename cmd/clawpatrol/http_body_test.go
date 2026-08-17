package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBufferHTTPBodyForMatchPreservesUpstreamForwardingBody(t *testing.T) {
	const body = `{"prompt":"please forward me"}`
	var upstreamBody string
	var upstreamContentLength int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamContentLength = r.ContentLength
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read body: %v", err)
		}
		upstreamBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	req, err := http.NewRequest("POST", upstream.URL+"/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	matchBody := bufferHTTPBodyForMatch(req, maxHTTPMatchBody)
	if string(matchBody) != body {
		t.Fatalf("match body = %q, want %q", matchBody, body)
	}
	if req.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if upstreamBody != body {
		t.Fatalf("upstream body = %q, want %q", upstreamBody, body)
	}
	if upstreamContentLength != int64(len(body)) {
		t.Fatalf("upstream ContentLength = %d, want %d", upstreamContentLength, len(body))
	}
}

func TestBufferHTTPBodyForMatchKeepsFullLargeForwardingBody(t *testing.T) {
	body := strings.Repeat("a", maxHTTPMatchBody) + "tail"
	var upstreamBodyLen int
	var upstreamContentLength int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamContentLength = r.ContentLength
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read body: %v", err)
		}
		upstreamBodyLen = len(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	req, err := http.NewRequest("POST", upstream.URL+"/large", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	matchBody := bufferHTTPBodyForMatch(req, maxHTTPMatchBody)
	if len(matchBody) != maxHTTPMatchBody {
		t.Fatalf("match body len = %d, want %d", len(matchBody), maxHTTPMatchBody)
	}
	if req.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if upstreamBodyLen != len(body) {
		t.Fatalf("upstream body len = %d, want %d", upstreamBodyLen, len(body))
	}
	if upstreamContentLength != int64(len(body)) {
		t.Fatalf("upstream ContentLength = %d, want %d", upstreamContentLength, len(body))
	}
}

// TestBufferHTTPBodyForMatchTruncatedFlagsOverflow pins the overflow
// signal the dispatcher needs to fail-close body-reading rules: an
// exact-cap body must NOT report truncated (no bytes were dropped),
// a one-byte-over body must, and the upstream forward must still
// receive the full original body in either case.
func TestBufferHTTPBodyForMatchTruncatedFlagsOverflow(t *testing.T) {
	cases := []struct {
		name          string
		bodyLen       int
		wantTruncated bool
	}{
		{"under cap", maxHTTPMatchBody / 2, false},
		{"exact cap", maxHTTPMatchBody, false},
		{"one byte over cap", maxHTTPMatchBody + 1, true},
		{"well over cap", maxHTTPMatchBody + 4096, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("x", tc.bodyLen)
			var upstreamLen int
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				upstreamLen = len(b)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()

			req, err := http.NewRequest("POST", upstream.URL+"/x", strings.NewReader(body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			match, truncated := bufferHTTPBodyForMatchTruncated(req, maxHTTPMatchBody)
			if truncated != tc.wantTruncated {
				t.Errorf("truncated = %v, want %v", truncated, tc.wantTruncated)
			}
			wantMatchLen := tc.bodyLen
			if wantMatchLen > maxHTTPMatchBody {
				wantMatchLen = maxHTTPMatchBody
			}
			if len(match) != wantMatchLen {
				t.Errorf("match len = %d, want %d", len(match), wantMatchLen)
			}

			resp, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			_ = resp.Body.Close()
			if upstreamLen != tc.bodyLen {
				t.Errorf("upstream got %d bytes, want %d (truncation must not drop bytes from the forwarded body)", upstreamLen, tc.bodyLen)
			}
		})
	}
}

func TestBufferHTTPBodyForMatchStreamsUnknownLengthRemainder(t *testing.T) {
	body := strings.Repeat("b", maxHTTPMatchBody) + "tail"
	var upstreamBodyLen int
	var upstreamContentLength int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamContentLength = r.ContentLength
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read body: %v", err)
		}
		upstreamBodyLen = len(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	req, err := http.NewRequest("POST", upstream.URL+"/chunked", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.ContentLength = -1

	matchBody := bufferHTTPBodyForMatch(req, maxHTTPMatchBody)
	if len(matchBody) != maxHTTPMatchBody {
		t.Fatalf("match body len = %d, want %d", len(matchBody), maxHTTPMatchBody)
	}
	if req.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1", req.ContentLength)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if upstreamBodyLen != len(body) {
		t.Fatalf("upstream body len = %d, want %d", upstreamBodyLen, len(body))
	}
	if upstreamContentLength != -1 {
		t.Fatalf("upstream ContentLength = %d, want -1", upstreamContentLength)
	}
}

// TestBufferHTTPBodyForMatchHonorsCustomCap verifies the rules-engine
// cap is honored when a non-default value is passed (the value the
// gateway threads through from gateway.limits.body_buffer): the
// match view is truncated to the custom cap while the upstream forward
// still receives every byte.
func TestBufferHTTPBodyForMatchHonorsCustomCap(t *testing.T) {
	const capBytes = 16
	body := strings.Repeat("z", capBytes) + "overflow"
	var upstreamLen int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamLen = len(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	req, err := http.NewRequest("POST", upstream.URL+"/cap", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	match, truncated := bufferHTTPBodyForMatchTruncated(req, capBytes)
	if !truncated {
		t.Fatalf("truncated = false, want true (body exceeds custom cap)")
	}
	if len(match) != capBytes {
		t.Fatalf("match len = %d, want %d", len(match), capBytes)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_ = resp.Body.Close()
	if upstreamLen != len(body) {
		t.Fatalf("upstream got %d bytes, want %d (custom cap must not drop forwarded bytes)", upstreamLen, len(body))
	}
}

func TestBufferHTTPBodyForMatchReadErrorPreservesPartialBodyAndFailsClosed(t *testing.T) {
	const prefix = `{"partial":true}`
	wantErr := errors.New("request body failed")
	req := &http.Request{
		Body:          &dataThenErrorReader{data: []byte(prefix), err: wantErr},
		ContentLength: int64(len(prefix) + 10),
		Header:        make(http.Header),
	}

	result := bufferHTTPBodyForMatchResult(req, maxHTTPMatchBody)
	if string(result.body) != prefix {
		t.Fatalf("match body = %q, want partial prefix %q", result.body, prefix)
	}
	if !result.truncated {
		t.Fatal("truncated = false, want true so body-dependent policy evaluation fails closed")
	}
	if result.complete {
		t.Fatal("complete = true after read error")
	}
	if !errors.Is(result.readErr, wantErr) {
		t.Fatalf("read error = %v, want %v", result.readErr, wantErr)
	}

	forwarded, err := io.ReadAll(req.Body)
	if !errors.Is(err, wantErr) {
		t.Fatalf("restored request body error = %v, want %v", err, wantErr)
	}
	if string(forwarded) != prefix {
		t.Fatalf("restored request body = %q, want %q", forwarded, prefix)
	}

	ev := Event{}
	applyTerminalRequestCapture(&ev, req, result, maxHTTPMatchBody)
	if ev.ReqBodyState != bodyCaptureAborted {
		t.Fatalf("capture state = %q, want %q", ev.ReqBodyState, bodyCaptureAborted)
	}
	if ev.ReqBody != prefix {
		t.Fatalf("captured request body = %q, want partial prefix %q", ev.ReqBody, prefix)
	}
	if ev.ReqSha != "" {
		t.Fatalf("aborted request SHA = %q, want empty", ev.ReqSha)
	}
}
