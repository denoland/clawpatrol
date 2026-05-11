package main

import (
	"bytes"
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
