package main

import (
	"bytes"
	"net/http"
	"strings"
)

// authResponseHeaders lists response header names that, on a
// credentialled MITM path, would hand the agent a usable
// authentication artifact even though the original injected
// credential never touched the agent's request.
//
// Set-Cookie / Set-Cookie2 carry session cookies and OAuth
// refresh-token cookies. WWW-Authenticate / Proxy-Authenticate
// carry challenges that some schemes piggy-back tokens onto.
// Authentication-Info / Proxy-Authentication-Info carry
// response-side auth state. None of them are needed by a
// non-authenticating agent to consume the response body.
var authResponseHeaders = []string{
	"Set-Cookie",
	"Set-Cookie2",
	"WWW-Authenticate",
	"Proxy-Authenticate",
	"Authentication-Info",
	"Proxy-Authentication-Info",
}

func isAuthResponseHeader(name string) bool {
	for _, n := range authResponseHeaders {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

// stripAuthResponseHeaders removes credential-bearing response
// headers in-place from a parsed http.Header.
func stripAuthResponseHeaders(h http.Header) {
	for _, name := range authResponseHeaders {
		h.Del(name)
	}
}

// stripAuthResponseHeadersRaw removes credential-bearing header
// lines from a raw HTTP response header block (status line +
// CRLF-separated headers + terminating CRLFCRLF). Used on the WS
// upgrade-response path where Go's http.Response.Write mangles
// Connection / Upgrade and would break the 101 handshake — we
// filter byte-verbatim here instead of round-tripping through
// http.Response.
func stripAuthResponseHeadersRaw(headerBytes []byte) []byte {
	const term = "\r\n\r\n"
	if !bytes.HasSuffix(headerBytes, []byte(term)) {
		return headerBytes
	}
	body := headerBytes[:len(headerBytes)-len(term)]
	lines := bytes.Split(body, []byte("\r\n"))
	kept := make([][]byte, 0, len(lines))
	for i, line := range lines {
		if i == 0 {
			kept = append(kept, line)
			continue
		}
		if c := bytes.IndexByte(line, ':'); c >= 0 {
			name := strings.TrimSpace(string(line[:c]))
			if isAuthResponseHeader(name) {
				continue
			}
		}
		kept = append(kept, line)
	}
	out := bytes.Join(kept, []byte("\r\n"))
	out = append(out, '\r', '\n', '\r', '\n')
	return out
}
