package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestStripAuthResponseHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Add("Set-Cookie", "session=abc")
	h.Add("Set-Cookie", "refresh=def")
	h.Set("Set-Cookie2", "legacy=ghi")
	h.Set("WWW-Authenticate", `Bearer realm="x"`)
	h.Set("Proxy-Authenticate", `Basic realm="x"`)
	h.Set("Authentication-Info", `nextnonce="x"`)
	h.Set("Proxy-Authentication-Info", `rspauth="x"`)
	h.Set("X-Custom", "keep")

	stripAuthResponseHeaders(h)

	for _, name := range []string{
		"Set-Cookie", "Set-Cookie2", "WWW-Authenticate",
		"Proxy-Authenticate", "Authentication-Info",
		"Proxy-Authentication-Info",
	} {
		if v := h.Values(name); len(v) != 0 {
			t.Errorf("header %q not stripped, got %v", name, v)
		}
	}
	if h.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type was clobbered: %q", h.Get("Content-Type"))
	}
	if h.Get("X-Custom") != "keep" {
		t.Errorf("X-Custom was clobbered: %q", h.Get("X-Custom"))
	}
}

func TestStripAuthResponseHeadersRaw(t *testing.T) {
	in := []byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: abc\r\n" +
		"set-cookie: session=abc\r\n" +
		"Set-Cookie: refresh=def\r\n" +
		"WWW-Authenticate: Bearer realm=\"x\"\r\n" +
		"X-Custom: keep\r\n" +
		"\r\n")
	out := stripAuthResponseHeadersRaw(in)

	s := string(out)
	for _, banned := range []string{
		"set-cookie", "Set-Cookie", "WWW-Authenticate",
		"session=abc", "refresh=def", "Bearer",
	} {
		if strings.Contains(s, banned) {
			t.Errorf("expected %q to be stripped, output:\n%s", banned, s)
		}
	}
	for _, kept := range []string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Accept: abc",
		"X-Custom: keep",
	} {
		if !strings.Contains(s, kept) {
			t.Errorf("expected %q preserved, output:\n%s", kept, s)
		}
	}
	if !bytes.HasSuffix(out, []byte("\r\n\r\n")) {
		t.Errorf("output does not end with CRLFCRLF: %q",
			string(out[max(0, len(out)-8):]))
	}
}

func TestStripAuthResponseHeadersRawNoTerminator(t *testing.T) {
	in := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: x=y\r\n")
	out := stripAuthResponseHeadersRaw(in)
	if !bytes.Equal(in, out) {
		t.Errorf("malformed input should pass through unchanged")
	}
}

// End-to-end: the MITM path strips Set-Cookie / Set-Cookie2 / WWW-
// Authenticate from the http.Response before resp.Write streams it
// to the client, AND from resp.Trailer so chunked-trailer fields
// don't get a back-door past the audit-log strip.
func TestStripAuthResponseHeadersThroughRespWrite(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"X-Keep":       {"yes"},
		},
		Trailer: http.Header{
			"X-Trailer-Keep": {"yes"},
		},
		Body:             io.NopCloser(strings.NewReader("hello")),
		ContentLength:    -1,
		TransferEncoding: []string{"chunked"},
	}
	resp.Header.Add("Set-Cookie", "session=abc")
	resp.Header.Add("Set-Cookie", "refresh=def")
	resp.Header.Set("Set-Cookie2", "legacy=ghi")
	resp.Header.Set("WWW-Authenticate", `Bearer realm="x"`)
	resp.Header.Set("Authentication-Info", `nextnonce="x"`)
	resp.Trailer.Add("Set-Cookie", "trailer=tok")
	resp.Trailer.Set("WWW-Authenticate", `Basic realm="t"`)

	stripAuthResponseHeaders(resp.Header)
	stripAuthResponseHeaders(resp.Trailer)

	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		t.Fatalf("resp.Write: %v", err)
	}
	wire := buf.String()
	for _, banned := range []string{
		"session=abc", "refresh=def", "legacy=ghi", "Bearer", "nextnonce",
		"trailer=tok", "Basic realm",
		"Set-Cookie", "Set-Cookie2", "WWW-Authenticate", "Authentication-Info",
	} {
		if strings.Contains(wire, banned) {
			t.Errorf("expected %q stripped, on-wire response:\n%s", banned, wire)
		}
	}
	for _, kept := range []string{"X-Keep: yes", "X-Trailer-Keep: yes", "hello"} {
		if !strings.Contains(wire, kept) {
			t.Errorf("expected %q preserved, on-wire response:\n%s", kept, wire)
		}
	}
	// Sanity: the body+trailer round-trips through http.ReadResponse.
	parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(wire)), nil)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if _, err := io.ReadAll(parsed.Body); err != nil {
		t.Fatalf("readback body: %v", err)
	}
	_ = parsed.Body.Close()
}

// Obs-fold (RFC 7230 §3.2.4): a header value can wrap across lines
// when the continuation line starts with SP / HTAB. Without
// continuation-aware stripping the parent Set-Cookie line gets
// removed but the cookie bytes on the wrapped lines survive and
// fold into the preceding header — which on a 101 response is the
// status line, corrupting the handshake AND leaking the cookie.
func TestStripAuthResponseHeadersRawObsFold(t *testing.T) {
	in := []byte("HTTP/1.1 200 OK\r\n" +
		"Set-Cookie: session=abc;\r\n" +
		" path=/;\r\n" +
		"\tdomain=example.com\r\n" +
		"X-Custom: keep\r\n" +
		"WWW-Authenticate: Bearer realm=\"x\",\r\n" +
		" error=\"invalid_token\"\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n")
	out := stripAuthResponseHeadersRaw(in)

	s := string(out)
	for _, banned := range []string{
		"Set-Cookie", "session=abc", "path=/", "domain=example.com",
		"WWW-Authenticate", "Bearer", "invalid_token",
	} {
		if strings.Contains(s, banned) {
			t.Errorf("expected %q to be stripped, output:\n%s", banned, s)
		}
	}
	for _, kept := range []string{
		"HTTP/1.1 200 OK",
		"X-Custom: keep",
		"Content-Type: text/plain",
	} {
		if !strings.Contains(s, kept) {
			t.Errorf("expected %q preserved, output:\n%s", kept, s)
		}
	}
	// Continuation lines from a kept header must still survive.
	in2 := []byte("HTTP/1.1 200 OK\r\n" +
		"X-Long: first\r\n" +
		" continuation\r\n" +
		"Set-Cookie: drop=me\r\n" +
		"\r\n")
	out2 := stripAuthResponseHeadersRaw(in2)
	s2 := string(out2)
	if !strings.Contains(s2, "X-Long: first") || !strings.Contains(s2, " continuation") {
		t.Errorf("kept-header continuation dropped, output:\n%s", s2)
	}
	if strings.Contains(s2, "drop=me") {
		t.Errorf("Set-Cookie not stripped, output:\n%s", s2)
	}
}
