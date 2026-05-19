package config

import (
	"fmt"
	"strings"
)

// MatchDashboardOperator reports whether login matches any entry in
// allowlist. Entries are either:
//
//   - "user@domain" — exact match against the whois login.
//   - "*@domain"    — matches any login ending in "@domain".
//
// Empty login never matches (a missing whois identity must not be
// papered over). Empty allowlist never matches.
func MatchDashboardOperator(login string, allowlist []string) bool {
	if login == "" {
		return false
	}
	for _, entry := range allowlist {
		if entry == login {
			return true
		}
		if strings.HasPrefix(entry, "*@") {
			// Strip the leading "*" only; the "@" stays in the
			// suffix so "*@example.com" doesn't match "evil-example.com".
			suffix := entry[1:]
			if len(login) > len(suffix) && strings.HasSuffix(login, suffix) {
				return true
			}
		}
	}
	return false
}

// ValidateDashboardOperatorEntry checks the shape of a single
// allowlist entry. Returns nil for "user@domain" or "*@domain", an
// error otherwise.
func ValidateDashboardOperatorEntry(entry string) error {
	if entry == "" {
		return fmt.Errorf("empty entry")
	}
	if strings.HasPrefix(entry, "*@") {
		domain := entry[2:]
		if domain == "" {
			return fmt.Errorf("wildcard entry must be \"*@<domain>\"")
		}
		if strings.ContainsAny(domain, "@*") {
			return fmt.Errorf("wildcard entry must be exactly \"*@<domain>\" (got %q)", entry)
		}
		return nil
	}
	if strings.ContainsRune(entry, '*') {
		return fmt.Errorf("only the leading \"*@\" wildcard is supported (got %q)", entry)
	}
	at := strings.IndexByte(entry, '@')
	if at <= 0 || at != strings.LastIndexByte(entry, '@') {
		return fmt.Errorf("operator must be \"user@domain\" (got %q)", entry)
	}
	if entry[at+1:] == "" {
		return fmt.Errorf("operator must be \"user@domain\" (got %q)", entry)
	}
	return nil
}
