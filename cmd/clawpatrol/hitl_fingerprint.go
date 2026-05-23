package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"unsafe"
)

const (
	HITLFingerprintVersionV1 = "v1"

	hitlRequestFingerprintDomainV1 = "clawpatrol hitl request fingerprint v1"
	hitlBodyFingerprintDomainV1    = "clawpatrol hitl body fingerprint v1"
)

var ErrHITLFingerprintInvalid = errors.New("invalid hitl fingerprint input")

type HITLFingerprintKey struct {
	ID   string
	Root []byte
}

type HITLFingerprintHeader struct {
	Name   string
	Values []string
}

type HITLRequestFingerprintInput struct {
	Key             HITLFingerprintKey
	ProfileID       string
	PrincipalID     string
	EndpointID      string
	ApprovalRuleID  string
	Method          string
	Scheme          string
	Host            string
	Path            string
	RawQuery        string
	SelectedHeaders []HITLFingerprintHeader
	RawBody         []byte
	AuthBindingID   string
}

type HITLRequestFingerprintResult struct {
	Version            string
	HMACKeyID          string
	BodyHMAC           string
	RequestFingerprint string
}

type HITLCredentialAuthBindingInput struct {
	ProfileID    string
	CredentialID string
	Generation   string
	SubjectID    string
}

func ComputeHITLRequestFingerprint(in HITLRequestFingerprintInput) (HITLRequestFingerprintResult, error) {
	if err := validateHITLFingerprintInput(in); err != nil {
		return HITLRequestFingerprintResult{}, err
	}

	normalizedHeaders, err := normalizeHITLFingerprintHeaders(in.SelectedHeaders)
	if err != nil {
		return HITLRequestFingerprintResult{}, err
	}
	in.SelectedHeaders = normalizedHeaders

	// Derive the two per-domain HMAC keys, then compute and encode
	// each fingerprint with the helpers below — each helper folds
	// the hex-encode + "hmac-sha256:" prefix into a single string
	// build, so the only per-call allocation is the final result
	// string. The previous shape went hex.EncodeToString → "..." +
	// → fmt.concat, allocating three intermediate strings per HMAC.
	bodyKey := deriveHITLHMACKeyString(in.Key.Root, hitlBodyFingerprintDomainV1)
	bodyHMAC := encodeHITLHMACSHA256(bodyKey, in.RawBody)

	canonical := canonicalHITLRequestV1(in, bodyHMAC)
	requestKey := deriveHITLHMACKeyString(in.Key.Root, hitlRequestFingerprintDomainV1)
	requestFingerprint := encodeHITLHMACSHA256(requestKey, canonical)

	return HITLRequestFingerprintResult{
		Version:            HITLFingerprintVersionV1,
		HMACKeyID:          in.Key.ID,
		BodyHMAC:           bodyHMAC,
		RequestFingerprint: requestFingerprint,
	}, nil
}

func SelectHITLFingerprintHeaders(headers http.Header, allowlist []string) ([]HITLFingerprintHeader, error) {
	if len(allowlist) == 0 {
		return nil, nil
	}
	selected := make([]HITLFingerprintHeader, 0, len(allowlist))
	for _, name := range allowlist {
		canonicalName := trimAndLowerASCII(name)
		if canonicalName == "" {
			return nil, fmt.Errorf("%w: empty fingerprint header allowlist entry", ErrHITLFingerprintInvalid)
		}
		if isForbiddenHITLFingerprintHeader(canonicalName) {
			return nil, fmt.Errorf("%w: header %q must not be used for HITL request fingerprinting", ErrHITLFingerprintInvalid, canonicalName)
		}
		// Allowlists are short (handful of entries), so a linear
		// dedup scan beats a map[string]struct{} for the hot path.
		// The previous map cost one allocation per call plus an
		// internal hmap entry per name; the slice scan touches
		// already-cached memory and stays O(n²) on n ≤ ~10.
		for _, prior := range selected {
			if prior.Name == canonicalName {
				return nil, fmt.Errorf("%w: duplicate fingerprint header %q", ErrHITLFingerprintInvalid, canonicalName)
			}
		}

		values := headers.Values(canonicalName)
		if len(values) == 0 {
			continue
		}
		trimmed := make([]string, len(values))
		for i, value := range values {
			trimmed[i] = trimSpaceASCII(value)
		}
		selected = append(selected, HITLFingerprintHeader{Name: canonicalName, Values: trimmed})
	}
	return selected, nil
}

func BuildHITLCredentialAuthBindingID(in HITLCredentialAuthBindingInput) (string, error) {
	if in.ProfileID == "" {
		return "", fmt.Errorf("%w: profile_id is required for auth binding", ErrHITLFingerprintInvalid)
	}
	if in.CredentialID == "" {
		return "", fmt.Errorf("%w: credential_id is required for auth binding", ErrHITLFingerprintInvalid)
	}
	if in.Generation == "" {
		return "", fmt.Errorf("%w: credential generation is required for auth binding", ErrHITLFingerprintInvalid)
	}

	var b bytes.Buffer
	writeHITLCanonicalField(&b, "kind", "credential")
	writeHITLCanonicalField(&b, "version", HITLFingerprintVersionV1)
	writeHITLCanonicalField(&b, "profile_id", in.ProfileID)
	writeHITLCanonicalField(&b, "credential_id", in.CredentialID)
	writeHITLCanonicalField(&b, "generation", in.Generation)
	writeHITLCanonicalField(&b, "subject_id", in.SubjectID)
	sum := sha256.Sum256(b.Bytes())
	return "credential:v1:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// validateHITLFingerprintInput checks the ten required string fields
// and the HMAC root. The old shape built a map[string]string per call
// just to drive a name/value iteration — 11+ allocs per fingerprint
// on the hot HITL relay path. Direct field checks here pay zero
// allocs on the happy path, and the error path still names which
// field failed so callers can debug a missing input.
func validateHITLFingerprintInput(in HITLRequestFingerprintInput) error {
	switch {
	case isBlankASCII(in.Key.ID):
		return errHITLFingerprintFieldRequired("hmac_key_id")
	case isBlankASCII(in.ProfileID):
		return errHITLFingerprintFieldRequired("profile_id")
	case isBlankASCII(in.PrincipalID):
		return errHITLFingerprintFieldRequired("principal_id")
	case isBlankASCII(in.EndpointID):
		return errHITLFingerprintFieldRequired("endpoint_id")
	case isBlankASCII(in.ApprovalRuleID):
		return errHITLFingerprintFieldRequired("approval_rule_id")
	case isBlankASCII(in.Method):
		return errHITLFingerprintFieldRequired("method")
	case isBlankASCII(in.Scheme):
		return errHITLFingerprintFieldRequired("scheme")
	case isBlankASCII(in.Host):
		return errHITLFingerprintFieldRequired("host")
	case isBlankASCII(in.Path):
		return errHITLFingerprintFieldRequired("path")
	case isBlankASCII(in.AuthBindingID):
		return errHITLFingerprintFieldRequired("auth_binding_id")
	}
	if len(in.Key.Root) == 0 {
		return fmt.Errorf("%w: hmac root key is required", ErrHITLFingerprintInvalid)
	}
	return nil
}

func errHITLFingerprintFieldRequired(name string) error {
	return fmt.Errorf("%w: %s is required", ErrHITLFingerprintInvalid, name)
}

// isBlankASCII reports whether s is empty or contains only ASCII
// whitespace (space, HTAB, CR, LF, VT, FF — the byte set
// unicode.IsSpace returns true for under the ASCII range, which is
// what strings.TrimSpace would peel off here). HTTP tokens are
// ASCII per RFC 7230 §3.2, so we don't need TrimSpace's full
// unicode iteration — and we skip TrimSpace's copy of any
// non-blank value, which is what makes this an alloc-free check
// on the hot HITL relay path.
func isBlankASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			continue
		default:
			return false
		}
	}
	return true
}

func normalizeHITLFingerprintHeaders(headers []HITLFingerprintHeader) ([]HITLFingerprintHeader, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	out := make([]HITLFingerprintHeader, len(headers))
	for i, h := range headers {
		name := trimAndLowerASCII(h.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: empty selected fingerprint header name", ErrHITLFingerprintInvalid)
		}
		if isForbiddenHITLFingerprintHeader(name) {
			return nil, fmt.Errorf("%w: header %q must not be used for HITL request fingerprinting", ErrHITLFingerprintInvalid, name)
		}
		values := make([]string, len(h.Values))
		for j, value := range h.Values {
			values[j] = trimSpaceASCII(value)
		}
		out[i] = HITLFingerprintHeader{Name: name, Values: values}
	}
	return out, nil
}

func canonicalHITLRequestV1(in HITLRequestFingerprintInput, bodyHMAC string) []byte {
	var b bytes.Buffer
	// Sized once for the typical request shape (a dozen canonical
	// fields, no selected headers): saves the buffer-growth realloc
	// chain bytes.Buffer would otherwise run on the first writes.
	const baseGrow = 384
	const perHeader = 96
	b.Grow(baseGrow + perHeader*len(in.SelectedHeaders))
	writeHITLCanonicalField(&b, "fingerprint_version", HITLFingerprintVersionV1)
	writeHITLCanonicalField(&b, "profile_id", in.ProfileID)
	writeHITLCanonicalField(&b, "principal_id", in.PrincipalID)
	writeHITLCanonicalField(&b, "endpoint_id", in.EndpointID)
	writeHITLCanonicalField(&b, "approval_rule_id", in.ApprovalRuleID)
	writeHITLCanonicalField(&b, "method", upperASCII(in.Method))
	writeHITLCanonicalField(&b, "scheme", lowerASCII(in.Scheme))
	writeHITLCanonicalField(&b, "host", lowerASCII(in.Host))
	writeHITLCanonicalField(&b, "path", in.Path)
	writeHITLCanonicalField(&b, "raw_query", in.RawQuery)
	writeHITLCanonicalIntField(&b, "selected_header_count", len(in.SelectedHeaders))
	for _, h := range in.SelectedHeaders {
		writeHITLCanonicalField(&b, "selected_header_name", lowerASCII(h.Name))
		writeHITLCanonicalIntField(&b, "selected_header_value_count", len(h.Values))
		for _, value := range h.Values {
			writeHITLCanonicalField(&b, "selected_header_value", trimSpaceASCII(value))
		}
	}
	writeHITLCanonicalField(&b, "body_hmac", bodyHMAC)
	writeHITLCanonicalField(&b, "auth_binding_id", in.AuthBindingID)
	return b.Bytes()
}

// writeHITLCanonicalIntField emits a length-prefixed (name=value) row
// whose value is an integer. Streams the digits directly into b via
// strconv.AppendInt instead of materializing a temporary string. Two
// disjoint scratch buffers because both AppendInt calls write into
// stack storage; sharing one buffer would corrupt the first result
// before the value is flushed.
func writeHITLCanonicalIntField(b *bytes.Buffer, name string, value int) {
	var valTmp [20]byte
	var lenTmp [20]byte
	digits := strconv.AppendInt(valTmp[:0], int64(value), 10)
	b.Write(strconv.AppendInt(lenTmp[:0], int64(len(name)), 10))
	b.WriteByte(':')
	b.WriteString(name)
	b.WriteByte('=')
	b.Write(strconv.AppendInt(lenTmp[:0], int64(len(digits)), 10))
	b.WriteByte(':')
	b.Write(digits)
	b.WriteByte('\n')
}

// upperASCII / lowerASCII return s with ASCII letters folded to the
// target case, returning the original string verbatim when no change
// is needed. Saves the strings.ToUpper / strings.ToLower copy on the
// common already-canonical input.
func upperASCII(s string) string {
	if !needsCaseFold(s, false) {
		return s
	}
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		buf[i] = c
	}
	return string(buf)
}

func lowerASCII(s string) string {
	if !needsCaseFold(s, true) {
		return s
	}
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	return string(buf)
}

// trimSpaceASCII returns s with leading and trailing SP/HTAB trimmed.
// HTTP header values per RFC 7230 §3.2 may carry OWS (SP/HTAB only),
// so trimming the unicode space set strings.TrimSpace looks for is
// unnecessary — and TrimSpace allocates a fresh string whenever it
// actually trims, where slicing into the original string here is
// alloc-free.
func trimSpaceASCII(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// needsCaseFold reports whether s contains an ASCII letter that
// would change under the requested fold direction. toLower=true asks
// whether any uppercase letter is present; toLower=false asks the
// converse. Strings already in canonical case (the common path for
// HTTP methods and scheme strings emitted by Go's net/http) skip the
// allocation entirely.
func needsCaseFold(s string, toLower bool) bool {
	if toLower {
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'A' && c <= 'Z' {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}

func writeHITLCanonicalField(b *bytes.Buffer, name, value string) {
	// len(string) returns the byte count on Go's UTF-8 strings, so the
	// previous len([]byte(name)) was making a fresh allocation just to
	// re-derive the same number. strconv.AppendInt writes into a stack
	// buffer to avoid strconv.Itoa's per-call string allocation.
	var tmp [20]byte
	b.Write(strconv.AppendInt(tmp[:0], int64(len(name)), 10))
	b.WriteByte(':')
	b.WriteString(name)
	b.WriteByte('=')
	b.Write(strconv.AppendInt(tmp[:0], int64(len(value)), 10))
	b.WriteByte(':')
	b.WriteString(value)
	b.WriteByte('\n')
}

func deriveHITLHMACKey(root []byte, domain string) []byte {
	return computeHITLHMAC(root, []byte(domain))
}

func computeHITLHMAC(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

// deriveHITLHMACKeyString returns the per-domain derived key as a 32-
// byte string. Strings avoid the per-call []byte alloc that the older
// deriveHITLHMACKey ([]byte) form imposed when the result was used as
// an HMAC key — hmac.New(.., key) accepts a byte slice but copies it
// internally, so handing in a string-backed slice (via the
// stringsharedmem cast below) skips one heap copy.
func deriveHITLHMACKeyString(root []byte, domain string) string {
	mac := hmac.New(sha256.New, root)
	_, _ = mac.Write(stringToBytesNoCopy(domain))
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	return string(sum[:])
}

// hitlHMACPrefix is the literal string the HITL fingerprint v1
// envelope prefixes every HMAC with. The constant is here so the
// alloc-saving encoder doesn't have to materialize the literal at
// each call site.
const hitlHMACPrefix = "hmac-sha256:"

// encodeHITLHMACSHA256 computes HMAC-SHA256(key, msg) and returns
// "hmac-sha256:" + hex(sum) as a single allocated string. The naive
// shape — hex.EncodeToString(mac.Sum(nil)) wrapped in "hmac-sha256:"
// + … — allocates the 32-byte sum, then the 64-byte hex string, then
// the 76-byte concat result; this version writes the prefix and
// hex-encoded sum directly into one buffer and string-converts once.
func encodeHITLHMACSHA256(key string, msg []byte) string {
	mac := hmac.New(sha256.New, stringToBytesNoCopy(key))
	_, _ = mac.Write(msg)
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	var out [len(hitlHMACPrefix) + 2*sha256.Size]byte
	copy(out[:], hitlHMACPrefix)
	hex.Encode(out[len(hitlHMACPrefix):], sum[:])
	return string(out[:])
}

// stringToBytesNoCopy reuses a string's backing bytes as a []byte
// without copying. The result MUST be treated as immutable — hmac
// copies the key into its inner/outer pads, so the alias only has to
// outlive that copy, which it does (the call is synchronous and the
// returned slice is not retained).
func stringToBytesNoCopy(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// hitlForbiddenHeaderMarkers names case-insensitive substrings that
// disqualify a header name from HITL fingerprint allowlists — same
// set we redact in flatHeaders. Encoded as a fixed-size array of
// constants so isForbiddenHITLFingerprintHeader doesn't have to
// allocate a slice literal on every call.
var hitlForbiddenHeaderMarkers = [...]string{"auth", "token", "secret", "key", "password", "cookie"}

func isForbiddenHITLFingerprintHeader(name string) bool {
	// HTTP header names are ASCII (RFC 7230 §3.2). Fold case via the
	// ASCII-only containsFoldASCII helper to avoid strings.ToLower's
	// per-call allocation when the caller passes a mixed-case name.
	for _, marker := range hitlForbiddenHeaderMarkers {
		if containsFoldASCII(name, marker) {
			return true
		}
	}
	switch {
	case equalFoldASCII(name, "user-agent"),
		equalFoldASCII(name, "date"),
		equalFoldASCII(name, "x-request-id"),
		equalFoldASCII(name, "traceparent"),
		equalFoldASCII(name, "via"),
		equalFoldASCII(name, "connection"),
		equalFoldASCII(name, "transfer-encoding"),
		equalFoldASCII(name, "accept-encoding"):
		return true
	}
	if len(name) >= 5 {
		// Inline lowercase prefix check — strings.HasPrefix(strings.ToLower(name), "x-b3-")
		// would allocate to lowercase the entire name just to look at
		// five characters.
		head := [5]byte{name[0], name[1], name[2], name[3], name[4]}
		for i, c := range head {
			if c >= 'A' && c <= 'Z' {
				head[i] = c + ('a' - 'A')
			}
		}
		if head == [5]byte{'x', '-', 'b', '3', '-'} {
			return true
		}
	}
	return false
}
