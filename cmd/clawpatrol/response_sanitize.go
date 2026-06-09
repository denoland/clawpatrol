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

// altSvcHeader advertises HTTP/3 (and other alternative services). The
// gateway intercepts HTTPS on TCP/443 and drops UDP/443, so letting the
// origin's Alt-Svc through would tell the agent to retry over QUIC —
// which the gateway can't MITM and now black-holes. Strip it so the
// agent never learns to leave the interceptable TCP path. (The UDP/443
// drop is the enforcement; this and the SVCB/HTTPS h3 strip just stop
// the agent from trying in the first place.)
const altSvcHeader = "Alt-Svc"

// stripAltSvc removes the Alt-Svc header in-place from a parsed
// http.Header.
func stripAltSvc(h http.Header) {
	h.Del(altSvcHeader)
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
//
// Obs-fold continuation lines (deprecated RFC 7230 §3.2.4 — a line
// beginning with SP / HTAB is folded into the preceding header's
// value) are dropped together with their parent line when the
// parent is an auth header. Otherwise the parent line would be
// removed but the continuation kept, and the receiving HTTP parser
// would re-attach the cookie bytes to whichever non-auth header
// landed above them — including the status line.
func stripAuthResponseHeadersRaw(headerBytes []byte) []byte {
	const term = "\r\n\r\n"
	if !bytes.HasSuffix(headerBytes, []byte(term)) {
		return headerBytes
	}
	body := headerBytes[:len(headerBytes)-len(term)]
	lines := bytes.Split(body, []byte("\r\n"))
	kept := make([][]byte, 0, len(lines))
	droppingFold := false
	for i, line := range lines {
		if i == 0 {
			kept = append(kept, line)
			droppingFold = false
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if droppingFold {
				continue
			}
			kept = append(kept, line)
			continue
		}
		if c := bytes.IndexByte(line, ':'); c >= 0 {
			name := strings.TrimSpace(string(line[:c]))
			if isAuthResponseHeader(name) || strings.EqualFold(name, altSvcHeader) {
				droppingFold = true
				continue
			}
		}
		droppingFold = false
		kept = append(kept, line)
	}
	out := bytes.Join(kept, []byte("\r\n"))
	out = append(out, '\r', '\n', '\r', '\n')
	return out
}
