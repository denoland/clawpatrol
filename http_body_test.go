package main

import (
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

	matchBody := bufferHTTPBodyForMatch(req)
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

	matchBody := bufferHTTPBodyForMatch(req)
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

	matchBody := bufferHTTPBodyForMatch(req)
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
