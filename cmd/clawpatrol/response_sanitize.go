package main

import (
	"bytes"
	"net/http"
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

// isAuthResponseHeaderBytes reports whether name (a header-name
// byte slice read directly off the wire) matches one of the
// credential-bearing response headers we strip. The raw header-strip
// path on WS upgrades reads field names out of a wire buffer, so we
// fold case in place rather than allocating a string per header.
func isAuthResponseHeaderBytes(name []byte) bool {
	// Trim leading / trailing OWS (HTAB / SP) per RFC 7230 §3.2.4.
	for len(name) > 0 && (name[0] == ' ' || name[0] == '\t') {
		name = name[1:]
	}
	for len(name) > 0 && (name[len(name)-1] == ' ' || name[len(name)-1] == '\t') {
		name = name[:len(name)-1]
	}
	for _, n := range authResponseHeaders {
		if equalFoldASCIIBytes(name, n) {
			return true
		}
	}
	return false
}

// equalFoldASCII compares two ASCII strings case-insensitively. HTTP
// field names are guaranteed ASCII (RFC 7230 §3.2), so this avoids
// strings.EqualFold's unicode folding which scans for non-ASCII
// runes before each comparison.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// equalFoldASCIIBytes is the []byte/string variant of equalFoldASCII.
func equalFoldASCIIBytes(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// stripAuthResponseHeaders removes credential-bearing response
// headers in-place from a parsed http.Header.
func stripAuthResponseHeaders(h http.Header) {
	if len(h) == 0 {
		return
	}
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
//
// Obs-fold continuation lines (deprecated RFC 7230 §3.2.4 — a line
// beginning with SP / HTAB is folded into the preceding header's
// value) are dropped together with their parent line when the
// parent is an auth header. Otherwise the parent line would be
// removed but the continuation kept, and the receiving HTTP parser
// would re-attach the cookie bytes to whichever non-auth header
// landed above them — including the status line.
//
// Implementation: walk lines via IndexByte and copy kept bytes into
// a single output buffer. The previous implementation allocated a
// per-line [][]byte slice plus a bytes.Join — significant per-WS
// alloc churn on connection bursts.
func stripAuthResponseHeadersRaw(headerBytes []byte) []byte {
	const termLen = 4 // "\r\n\r\n"
	if len(headerBytes) < termLen ||
		headerBytes[len(headerBytes)-4] != '\r' ||
		headerBytes[len(headerBytes)-3] != '\n' ||
		headerBytes[len(headerBytes)-2] != '\r' ||
		headerBytes[len(headerBytes)-1] != '\n' {
		return headerBytes
	}
	body := headerBytes[:len(headerBytes)-termLen]
	out := make([]byte, 0, len(headerBytes))
	droppingFold := false
	first := true
	for len(body) > 0 {
		var line []byte
		if idx := bytes.Index(body, []byte("\r\n")); idx >= 0 {
			line = body[:idx]
			body = body[idx+2:]
		} else {
			line = body
			body = nil
		}
		if first {
			out = append(out, line...)
			out = append(out, '\r', '\n')
			droppingFold = false
			first = false
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if droppingFold {
				continue
			}
			out = append(out, line...)
			out = append(out, '\r', '\n')
			continue
		}
		if c := bytes.IndexByte(line, ':'); c >= 0 {
			if isAuthResponseHeaderBytes(line[:c]) {
				droppingFold = true
				continue
			}
		}
		droppingFold = false
		out = append(out, line...)
		out = append(out, '\r', '\n')
	}
	out = append(out, '\r', '\n')
	return out
}
