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
// third_party/tailscale/client/web/web.go — prefer Sec-Fetch-Site,
// fall back to Origin — with two differences.
//
// First, the Origin/Host comparison is backed by two things upstream
// does not need. A proxy in front of the dashboard may rewrite Host to
// a backend name, so `public_url` — the operator's declaration of the
// external URL — is accepted as an Origin outright. And the Host the
// comparison falls back to must itself be a name the gateway answers
// for, because a DNS rebinding attack makes Origin and Host agree on a
// name the attacker owns. That is also why Sec-Fetch-Site:
// same-origin is not enough on its own: a rebound page *is*
// same-origin with the dashboard, and says so. See csrfOriginIsOwn.
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
			w.csrfProtectRead(rw, r, next)
			return
		}
		// authPublic covers the device-flow handshakes `clawpatrol
		// join` drives (/api/onboard/{start,poll,claim}).
		// authSelfAuthenticating covers /api/cred/* and the HITL
		// operation-status paths, whose callers are external providers
		// and peer daemons that prove themselves per request (Slack's
		// v0 HMAC signature, a peer bearer token) and send no browser
		// headers at all.
		//
		// The login form is the exception among the public routes. Its
		// POST is only ever submitted by the dashboard's own page, and
		// on a gateway that has no root row yet it *sets* the root
		// password — so a cross-site submission to a fresh gateway
		// would choose the operator's password for them. SameSite=Lax
		// is no help there: first-run setup presents no cookie to
		// withhold. GET still renders the form for anyone.
		switch w.authRequirementForPath(r.URL.Path) {
		case authPublic:
			if r.URL.Path != dashboardLoginPath {
				next.ServeHTTP(rw, r)
				return
			}
		case authSelfAuthenticating:
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

		// A browser reporting anything but same-origin has told us
		// outright that another site initiated this.
		if secFetchSite != "" && secFetchSite != "same-origin" {
			http.Error(rw, fmt.Sprintf("CSRF request denied with Sec-Fetch-Site %q", secFetchSite), http.StatusForbidden)
			return
		}

		if origin == "" {
			// Sec-Fetch-Site said same-origin but no Origin came with
			// it. A browser sets Origin on every non-GET request, so
			// this is not a shape one produces; fall back to the name
			// the request was addressed to.
			if !w.csrfHostAllowed(r.Host) {
				http.Error(rw, fmt.Sprintf("CSRF request denied with no Origin header and unrecognized Host %q", r.Host), http.StatusForbidden)
				return
			}
			next.ServeHTTP(rw, r)
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
		if !w.csrfOriginIsOwn(parsed, r) {
			http.Error(rw, fmt.Sprintf("CSRF request denied with Origin %q for Host %q — set `public_url` to the URL the dashboard is reached on", origin, r.Host), http.StatusForbidden)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// csrfOriginIsOwn reports whether the browser's Origin identifies this
// dashboard. Either of two things establishes that.
//
// The declared external URL. `public_url` is the operator's statement
// of where the dashboard is reached, so it holds whatever a proxy in
// front of the dashboard rewrote Host to. Its scheme is declared too,
// so it is compared.
//
// Otherwise the request's own Host, matched in full including the
// port. That full match is what makes this tight: a page the agent
// serves on another port of the operator's machine, or from an address
// of its own, is a different origin and says so. The Host must also
// name something the gateway answers for, which is what catches a
// rebound name — that agrees with Origin by construction.
//
// On the Host half the scheme is only compared when the request itself
// proves one. A TLS request cannot have been initiated by a plaintext
// page on the same name, so `http://` is refused there; a plaintext
// request is either a plain-HTTP dashboard or a proxy that terminated
// TLS upstream, and those are indistinguishable from here. Anyone able
// to forge a page on the gateway's own name over plaintext is already
// astride that same plaintext request and needs no forgery.
//
// Every comparison is between canonical origins — default port folded
// away, lowercased — so `https://gw:443` and `https://gw` are one
// origin, and `https://gw:9999` is not.
func (w *webMux) csrfOriginIsOwn(origin *url.URL, r *http.Request) bool {
	if origin == nil || origin.Host == "" {
		return false
	}
	want := csrfCanonicalOrigin(origin.Scheme, origin.Host)
	if want == "" {
		return false
	}
	declared := w.csrfDeclaredOrigin()
	if declared != "" && declared == want {
		return true
	}
	if r.Host == "" {
		return false
	}
	if !w.csrfHostAllowed(r.Host) {
		return false
	}
	// The request carries no scheme of its own, so compare the Origin's
	// against whichever ones this request could have come from.
	schemes := []string{"https", "http"}
	switch {
	case r.TLS != nil:
		// TLS proves it: a plaintext page on this name did not send this.
		schemes = []string{"https"}
	case declared != "" && csrfSameHost(declared, want):
		// public_url names this host, so it is authoritative about the
		// host's scheme. Accepting the other one here is what would let
		// a plaintext page reach a dashboard the operator declared over
		// HTTPS and a proxy terminates TLS for. Only the scheme is
		// pinned — the same host on another port is still the dashboard.
		schemes = []string{csrfSchemeOfOrigin(declared)}
	}
	for _, scheme := range schemes {
		if csrfCanonicalOrigin(scheme, r.Host) == want {
			return true
		}
	}
	return false
}

// csrfSameHost reports whether two canonical origins name the same
// host, ignoring scheme and port.
func csrfSameHost(a, b string) bool {
	return csrfHostOfOrigin(a) == csrfHostOfOrigin(b) && csrfHostOfOrigin(a) != ""
}

// csrfSchemeOfOrigin pulls the scheme out of a canonical origin.
func csrfSchemeOfOrigin(origin string) string {
	scheme, _, _ := strings.Cut(origin, "://")
	return scheme
}

// csrfHostOfOrigin pulls the host out of a canonical origin, keeping an
// IPv6 literal's brackets so "[::1]" cannot collide with a name.
func csrfHostOfOrigin(origin string) string {
	_, rest, ok := strings.Cut(origin, "://")
	if !ok {
		return ""
	}
	if strings.HasPrefix(rest, "[") {
		if i := strings.Index(rest, "]"); i >= 0 {
			return rest[:i+1]
		}
		return ""
	}
	host, _, _ := strings.Cut(rest, ":")
	return host
}

// csrfDeclaredPublicURL returns the operator's `public_url`, read from
// the live config. A hot reload may retire or replace the value and the
// retired hostname has to stop being trusted with it, so the live
// config is authoritative even when it declares nothing. The value
// captured at construction is a fallback only for a mux with no config
// to read at all; in tsnet mode public_url is auto-derived from the
// Funnel cert domain after the node comes up, well after newWebMux ran,
// so the live one is also the only one that ever has it.
func (w *webMux) csrfDeclaredPublicURL() string {
	if w.g != nil {
		if cfg := w.g.cfg.Load(); cfg != nil {
			// Whatever the live config says, including nothing: a reload
			// that removes public_url has to retire the origin, so an
			// empty live value must not fall through to the captured one.
			return strings.TrimSpace(cfg.PublicURL())
		}
	}
	return strings.TrimSpace(w.publicURL)
}

// csrfDeclaredOrigin returns the canonical origin of `public_url`, or
// "" when none is configured.
func (w *webMux) csrfDeclaredOrigin() string {
	return csrfOriginOfURL(w.csrfDeclaredPublicURL())
}

// csrfOriginOfURL returns the canonical origin of a configured URL.
// public_url is stored either as a full URL or as a bare hostname (the
// tsnet Funnel derivation sets the latter, and Funnel is HTTPS-only),
// so both forms are accepted.
func csrfOriginOfURL(raw string) string {
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
	return csrfCanonicalOrigin(u.Scheme, u.Host)
}

// csrfCanonicalOrigin renders "scheme://host[:port]" with the scheme's
// default port folded away, so the two spellings a browser and a
// config file may use for one origin compare equal. An authority with
// no host has no origin.
func csrfCanonicalOrigin(scheme, authority string) string {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" || authority == "" {
		return ""
	}
	host, port := authority, ""
	if h, p, err := net.SplitHostPort(authority); err == nil {
		host, port = h, p
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return ""
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	// An IPv6 literal is bracketed in an origin whether or not a port
	// follows it, so the brackets go back on after the port is folded
	// away — otherwise "[::1]:443" and "[::1]" render differently.
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}

// csrfProtectRead holds a read of the JSON API to the name it was
// addressed to, and to the browser's account of who asked for it.
//
// A read needs its own check because the one above it has nothing to
// work with: a browser sends no Origin on a GET, so the Origin
// comparison that carries a state-changing request is simply absent,
// and a read of /api/state, /api/config, /api/events,
// /api/hitl/pending or /api/onboard/lookup returns exactly the
// internal state an attacker is after. The request arrives
// authenticated, too — a rebound page holds no cp_session, because
// that cookie belongs to the dashboard's real origin, and a cookieless
// request is the one dashboardAuthGate hands to tailnetGate, which
// takes its principal from the peer address: the operator's own
// machine.
//
// So the Host must name something the gateway answers for. That is
// what a rebound name fails: the page was served from a name the
// attacker owns, and the browser addresses the request to it.
//
// Document paths are left to the Host check alone. The Sec-Fetch-Site
// requirement would reject a top-level navigation into the dashboard
// from a link elsewhere, which reports "cross-site", and from a page
// on a sibling name, which reports "same-site" — both legitimate ways
// to arrive at the dashboard, and neither able to read a response.
//
// The open surface is csrfGuardedRead's.
func (w *webMux) csrfProtectRead(rw http.ResponseWriter, r *http.Request, next http.Handler) {
	if !csrfGuardedRead(w.authRequirementForPath(r.URL.Path)) {
		next.ServeHTTP(rw, r)
		return
	}
	if !w.csrfHostAllowed(r.Host) {
		http.Error(rw, fmt.Sprintf("read denied for unrecognized Host %q — set `public_url` or `dashboard_hosts` to the name the dashboard is reached on", r.Host), http.StatusForbidden)
		return
	}
	// A browser that names another site as the initiator of an API read
	// has told us so outright. CORS already keeps such a response from
	// being read, so this is a second lock on the same door; the Host
	// above is the one that holds rebinding shut, which is what makes
	// the header's absence survivable.
	//
	// Absent, the header decides nothing. Fetch Metadata is only
	// attached to a request whose URL is potentially trustworthy, so a
	// dashboard served as plain HTTP on a tailnet address gets none of
	// it — the lock engages on the Funnel, on a TLS-terminating proxy
	// and on loopback. Non-browser callers send none either: the
	// `clawpatrol` daemon polling /api/env-pushdown, an operator's
	// curl. "none" is the user themself — a typed URL or a bookmark.
	if strings.HasPrefix(r.URL.Path, "/api/") {
		switch site := r.Header.Get("Sec-Fetch-Site"); site {
		case "", "same-origin", "none":
		default:
			http.Error(rw, fmt.Sprintf("cross-site read denied with Sec-Fetch-Site %q", site), http.StatusForbidden)
			return
		}
	}
	next.ServeHTTP(rw, r)
}

// csrfGuardedRead reports whether a read of a route in this auth class
// has to name a Host the gateway answers for.
//
// Two classes are deliberately left open, because rebinding buys an
// attacker nothing on either.
//
// authPublic is the surface a client with no credential at all reads:
// /info, /ca.crt, the login form and the assets it loads. None of it
// is gated, so none of it is anything the attacker could not fetch
// directly, and holding it to the set would mean `clawpatrol join`
// could only name the gateway the way the gateway names itself.
//
// authSelfAuthenticating routes carry their own proof per request — a
// peer bearer token on /api/env-pushdown, an operation status token on
// the HITL paths. A page cannot produce either, so the response is not
// one a rebound name unlocks, and the callers are daemons addressing
// the gateway by whatever URL they joined with.
//
// Every other class is gated by something a rebound page does get for
// free: the dashboard session it does not need, because its absence is
// what hands the request to tailnetGate, which reads the principal off
// the peer address.
func csrfGuardedRead(req authRequirement) bool {
	switch req {
	case authPublic, authSelfAuthenticating:
		return false
	}
	return true
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

// csrfHostAllowed reports whether host (the request's Host, "name" or
// "name:port") names a destination the gateway serves the dashboard
// on. It judges where the request was addressed, never where it came
// from — csrfOriginIsOwn is what judges an Origin, and it compares
// full authorities, because the rules here are deliberately loose
// about the port and accept any IP literal.
//
// Its job is to reject a name that resolves to the gateway without
// being one of the gateway's own: that is the rebinding case, where
// Origin and Host agree and the comparison alone sees nothing wrong —
// and, on a read, where there is no Origin to compare at all.
//
// The dashboard binds on several listeners — loopback, the WireGuard
// netstack, the tsnet node, optionally a Funnel domain — so the set is
// assembled from what the gateway knows about itself. `dashboard_hosts`
// extends it with names only the operator knows the gateway is reached
// on: a proxy that rewrites Host to a backend name, or a CNAME in front
// of the dashboard.
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
	if h := csrfHostOfURL(w.csrfDeclaredPublicURL()); h != "" && h == lower {
		return true
	}
	if w.g == nil {
		return false
	}
	if cfg := w.g.cfg.Load(); cfg != nil {
		if h := csrfHostOfListen(cfg.DashboardListen()); h != "" && h == lower {
			return true
		}
		for _, declared := range cfg.DashboardHosts() {
			if h := csrfDeclaredHostname(declared); h != "" && h == lower {
				return true
			}
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

// csrfDeclaredHostname normalises one `dashboard_hosts` entry to a
// bare lowercased hostname. An entry may be written as a hostname, as
// "host:port", or as a full URL; the port and scheme carry no meaning
// here because the set judges the name alone.
func csrfDeclaredHostname(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	if strings.Contains(entry, "//") {
		return csrfHostOfURL(entry)
	}
	host := entry
	if h, _, err := net.SplitHostPort(entry); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return strings.ToLower(strings.TrimSuffix(host, "."))
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
