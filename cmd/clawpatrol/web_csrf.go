package main

import (
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// csrfProtect rejects state-changing requests a browser was tricked
// into sending from another site.
//
// It sits outside dashboardAuthGate, so it covers every protected
// route including the ones the gate hands to tailnetGate. That
// placement is what makes it effective: tailnetGate attributes a
// principal from the peer address of the connection (r.RemoteAddr →
// whois), so a request that carries no cp_session cookie is still
// authenticated as whoever owns the calling machine. The cookie is
// SameSite=Lax, which means a cross-site POST arrives *without* it —
// on the very path that authenticates by address instead. Any check
// placed inside the gate would be skipped by exactly the requests
// that need it.
//
// The shape follows the vendored upstream at
// third_party/tailscale/client/web/web.go: prefer Sec-Fetch-Site,
// fall back to comparing Origin against Host. Two things are added on
// top.
//
// First, a Host allowlist. Origin == Host is satisfied by a DNS
// rebinding attack — the attacker's name resolves to the gateway, so
// the browser reports the attacker's origin as same-origin and sends
// Sec-Fetch-Site: same-origin. Comparing the two headers against each
// other cannot see that. Requiring Host to be a name the gateway
// actually answers for can.
//
// Second, requests carrying neither header are allowed through
// unless they are shaped like a submitted form. Every browser sets
// Origin on a request whose method is not GET or HEAD, so a page
// cannot drive a request into that bucket; what lands there is the
// `clawpatrol` CLI, which POSTs to operator-gated endpoints
// (/api/onboard/approve during `join --login` self-approval) with no
// browser headers at all. Rejecting the bucket outright would turn
// every such call into a 403. The content-type filter keeps the
// allowance from covering the one thing a cross-site page could
// still express if some client omitted both headers: an HTML form
// submission.
//
// Requests are only ever rejected here — a pass still has the full
// auth chain in front of it.
func (w *webMux) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !csrfRelevantMethod(r.Method) {
			next.ServeHTTP(rw, r)
			return
		}
		// authPublic covers the device-flow handshakes `clawpatrol
		// join` drives (/api/onboard/{start,poll,claim}) and the login
		// form itself. authSelfAuthenticating covers /api/cred/* and
		// the HITL operation-status paths, whose callers are external
		// providers and peer daemons that prove themselves per
		// request (Slack's v0 HMAC signature, a peer bearer token) and
		// send no browser headers at all.
		switch w.authRequirementForPath(r.URL.Path) {
		case authPublic, authSelfAuthenticating:
			next.ServeHTTP(rw, r)
			return
		}

		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		origin := r.Header.Get("Origin")

		if secFetchSite == "" && origin == "" {
			if ct := csrfFormContentType(r.Header.Get("Content-Type")); ct != "" {
				http.Error(rw, fmt.Sprintf("CSRF request denied: form content type %q with no Origin or Sec-Fetch-Site header", ct), http.StatusForbidden)
				return
			}
			next.ServeHTTP(rw, r)
			return
		}

		// A browser is driving this request. Its notion of "same
		// origin" is only worth as much as the name it resolved, so
		// check the name first.
		if !w.csrfHostAllowed(r.Host) {
			http.Error(rw, fmt.Sprintf("CSRF request denied with unrecognized Host %q — set `public_url` to the hostname the dashboard is reached on", r.Host), http.StatusForbidden)
			return
		}

		if secFetchSite != "" {
			if secFetchSite == "same-origin" {
				next.ServeHTTP(rw, r)
				return
			}
			http.Error(rw, fmt.Sprintf("CSRF request denied with Sec-Fetch-Site %q", secFetchSite), http.StatusForbidden)
			return
		}

		// No Sec-Fetch-Site, so this is an older browser or a plain
		// HTTP origin. Compare Origin against Host.
		if r.Host == "" {
			http.Error(rw, "CSRF request denied with no Host header", http.StatusForbidden)
			return
		}
		parsed, err := url.Parse(origin)
		if err != nil {
			http.Error(rw, fmt.Sprintf("CSRF request denied with invalid Origin %q", origin), http.StatusForbidden)
			return
		}
		// A form POST from a sandboxed iframe or a data: URL sends
		// "Origin: null", which parses to an empty host.
		if parsed.Host == "" {
			http.Error(rw, fmt.Sprintf("CSRF request denied with no host in the Origin %q", origin), http.StatusForbidden)
			return
		}
		if !strings.EqualFold(parsed.Host, r.Host) {
			http.Error(rw, fmt.Sprintf("CSRF request denied with mismatched Origin %q and Host %q", parsed.Host, r.Host), http.StatusForbidden)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// csrfRelevantMethod reports whether a method can change state and so
// needs the origin check. GET, HEAD and OPTIONS are the methods a
// browser issues for navigation, subresource loads and preflights.
func csrfRelevantMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// csrfFormContentType returns the media type when it is one of the
// three a cross-site HTML form can produce, and "" otherwise.
// Anything else requires fetch()/XHR, which a cross-origin page
// cannot use here: the preflight needs CORS response headers the
// dashboard never sends.
func csrfFormContentType(header string) string {
	if header == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(header)
	if err != nil {
		// An unparseable content type is not one a form produces.
		return ""
	}
	switch mt {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return mt
	}
	return ""
}

// csrfHostAllowed reports whether host (the request's Host header,
// "name" or "name:port") is one the gateway serves the dashboard on.
// It bounds the Origin == Host comparison: without it, a name the
// attacker controls that resolves to the gateway satisfies the
// comparison and reads as same-origin to the browser.
//
// The dashboard binds on several listeners — loopback, the WireGuard
// netstack, the tsnet node, optionally a Funnel domain — so the set
// is assembled from what the gateway knows about itself rather than
// configured separately.
func (w *webMux) csrfHostAllowed(host string) bool {
	if host == "" {
		return false
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	if name == "" {
		return false
	}

	// An IP literal cannot be rebound: for Origin to match, the page
	// that issued the request was served from this same address, which
	// is the gateway itself.
	if net.ParseIP(name) != nil {
		return true
	}
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	if h := csrfHostOfURL(w.publicURL); h != "" && h == lower {
		return true
	}
	if w.g == nil {
		return false
	}
	if cfg := w.g.cfg.Load(); cfg != nil {
		// Read live as well as from the struct: in tsnet mode
		// public_url is auto-derived from the Funnel cert domain after
		// the node comes up, well after newWebMux ran.
		if h := csrfHostOfURL(cfg.PublicURL()); h != "" && h == lower {
			return true
		}
		if h := csrfHostOfListen(cfg.DashboardListen()); h != "" && h == lower {
			return true
		}
	}
	// The tsnet node's MagicDNS label, reached either bare or as the
	// full `<node>.<tailnet>.ts.net`. The suffix is required so the
	// label alone cannot be borrowed by a name the attacker owns.
	if tsName := strings.ToLower(w.g.tailscaleHostname); tsName != "" {
		if lower == tsName {
			return true
		}
		if strings.HasPrefix(lower, tsName+".") && strings.HasSuffix(lower, ".ts.net") {
			return true
		}
	}
	return false
}

// csrfHostOfURL extracts the lowercased hostname from a configured
// URL. public_url is stored either as a full URL or as a bare
// hostname (the tsnet Funnel derivation sets the latter), so both
// forms are accepted.
func csrfHostOfURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "//") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// csrfHostOfListen extracts a hostname from a bind address. A
// wildcard or empty bind names no host, so it contributes nothing.
func csrfHostOfListen(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return ""
	}
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	switch host {
	case "", "0.0.0.0", "::", "*":
		return ""
	}
	if net.ParseIP(host) != nil {
		// IP literals are already accepted wholesale above.
		return ""
	}
	return host
}
