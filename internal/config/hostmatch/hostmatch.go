// Package hostmatch parses and matches the host entries that appear
// in an endpoint's `hosts = [...]` list. Entries may be exact
// `api.foo.com`, port-qualified `api.foo.com:443`, IP literals
// `10.0.0.5`, IPv6 literals `[fd00::1]:22`, or wildcard suffixes
// `*.foo.com` (optionally port-qualified).
//
// Wildcards take the form `*.<suffix>`: a single `*` at the leftmost
// label, immediately followed by `.`, followed by a non-empty
// hostname containing no further metacharacters. `*.foo.com` matches
// any name that ends in `.foo.com` and has at least one character
// before that suffix — both `s3.foo.com` and `s3.us-east-1.foo.com`
// match, but the bare `foo.com` does not. Single-label restriction
// (RFC 6125 TLS cert wildcards) is deliberately NOT applied: the
// matching here is for endpoint routing, not certificate validation,
// and the operator use case (e.g. `*.amazonaws.com`) needs to span
// multiple label depths.
package hostmatch

import (
	"fmt"
	"net"
	"strings"
)

// IsWildcardHost reports whether the host portion of entry is a
// wildcard pattern. entry may carry a `:port` suffix.
func IsWildcardHost(entry string) bool {
	host, _, err := SplitHostPort(entry)
	if err != nil {
		return false
	}
	return strings.HasPrefix(host, "*.")
}

// SplitHostPort separates a `host[:port]` entry into its parts. For
// bare hosts it returns port="". Unlike net.SplitHostPort it does
// NOT error on the bare-host case — the caller (an endpoint's hosts
// list) routinely accepts both forms.
//
// Wildcard hosts like `*.foo.com` pass through unchanged in the
// host return; `*.foo.com:443` separates as host=`*.foo.com`,
// port=`443`.
func SplitHostPort(entry string) (host, port string, err error) {
	if entry == "" {
		return "", "", fmt.Errorf("empty host entry")
	}
	// Bracketed IPv6 with port: [::1]:22.
	if strings.HasPrefix(entry, "[") {
		h, p, splitErr := net.SplitHostPort(entry)
		if splitErr != nil {
			return "", "", splitErr
		}
		return h, p, nil
	}
	// Count colons: zero means bare host, exactly one means host:port,
	// more than one means an unbracketed IPv6 literal (caller intent
	// unclear — let net.SplitHostPort error out).
	switch strings.Count(entry, ":") {
	case 0:
		return entry, "", nil
	case 1:
		h, p, splitErr := net.SplitHostPort(entry)
		if splitErr != nil {
			return "", "", splitErr
		}
		return h, p, nil
	default:
		// Likely an unbracketed IPv6 literal without port. Treat the
		// whole string as the host. (Bare IPv6 hosts in HCL are
		// uncommon — the well-formed shape is [::1] — but we don't
		// want to reject them outright.)
		return entry, "", nil
	}
}

// ValidateHost checks that entry is a syntactically valid host entry.
// Accepts exact hostnames, IP literals, port-qualified forms, and
// `*.<suffix>` wildcards. Returns an error explaining what's wrong
// when entry doesn't fit any of those.
func ValidateHost(entry string) error {
	host, port, err := SplitHostPort(entry)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("missing host portion")
	}
	if strings.HasSuffix(entry, ":") && port == "" {
		return fmt.Errorf("trailing colon with no port: %q", entry)
	}
	if port != "" {
		if !isNumericPort(port) {
			return fmt.Errorf("invalid port %q", port)
		}
	}
	if strings.HasPrefix(host, "*.") {
		return validateWildcardSuffix(host)
	}
	if strings.ContainsRune(host, '*') {
		return fmt.Errorf("%q: `*` only allowed as leftmost label (use `*.<suffix>`)", host)
	}
	// Otherwise: exact hostname or IP. We don't enforce DNS-label
	// rules (clawpatrol has historically accepted any non-empty
	// string, and operators occasionally use synthetic names that
	// don't pass strict DNS validation).
	return nil
}

func validateWildcardSuffix(host string) error {
	suffix := host[2:] // strip "*."
	if suffix == "" {
		return fmt.Errorf("%q: wildcard suffix is empty", host)
	}
	if strings.ContainsRune(suffix, '*') {
		return fmt.Errorf("%q: only one `*` allowed", host)
	}
	if strings.HasPrefix(suffix, ".") || strings.HasSuffix(suffix, ".") {
		return fmt.Errorf("%q: wildcard suffix must not start or end with `.`", host)
	}
	if strings.Contains(suffix, "..") {
		return fmt.Errorf("%q: empty label in wildcard suffix", host)
	}
	if net.ParseIP(suffix) != nil {
		return fmt.Errorf("%q: wildcard suffix must not be an IP literal", host)
	}
	if !strings.Contains(suffix, ".") {
		// Refuse single-label suffixes like `*.com` — too broad to
		// be a routing target. Operators who really want this can
		// list specific TLDs.
		return fmt.Errorf("%q: wildcard suffix must contain at least one `.` (refuse to match a whole TLD)", host)
	}
	return nil
}

func isNumericPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n >= 1 && n <= 65535
}

// MatchWildcard reports whether the lowercased hostname matches the
// wildcard pattern. pattern must be a validated `*.<suffix>` form;
// hostname must be a bare host (no port). Both should already be
// lowercased — this function does no case folding.
func MatchWildcard(pattern, hostname string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // e.g. ".foo.com"
	if len(hostname) <= len(suffix) {
		return false
	}
	return strings.HasSuffix(hostname, suffix)
}
