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
	"strings"
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

	bodyKey := deriveHITLHMACKey(in.Key.Root, hitlBodyFingerprintDomainV1)
	bodyHMAC := "hmac-sha256:" + hex.EncodeToString(computeHITLHMAC(bodyKey, in.RawBody))

	canonical := canonicalHITLRequestV1(in, bodyHMAC)
	requestKey := deriveHITLHMACKey(in.Key.Root, hitlRequestFingerprintDomainV1)
	requestFingerprint := "hmac-sha256:" + hex.EncodeToString(computeHITLHMAC(requestKey, canonical))

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
	seen := make(map[string]struct{}, len(allowlist))
	selected := make([]HITLFingerprintHeader, 0, len(allowlist))
	for _, name := range allowlist {
		canonicalName := strings.ToLower(strings.TrimSpace(name))
		if canonicalName == "" {
			return nil, fmt.Errorf("%w: empty fingerprint header allowlist entry", ErrHITLFingerprintInvalid)
		}
		if isForbiddenHITLFingerprintHeader(canonicalName) {
			return nil, fmt.Errorf("%w: header %q must not be used for HITL request fingerprinting", ErrHITLFingerprintInvalid, canonicalName)
		}
		if _, ok := seen[canonicalName]; ok {
			return nil, fmt.Errorf("%w: duplicate fingerprint header %q", ErrHITLFingerprintInvalid, canonicalName)
		}
		seen[canonicalName] = struct{}{}

		values := headers.Values(canonicalName)
		if len(values) == 0 {
			continue
		}
		trimmed := make([]string, 0, len(values))
		for _, value := range values {
			trimmed = append(trimmed, strings.TrimSpace(value))
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

func validateHITLFingerprintInput(in HITLRequestFingerprintInput) error {
	required := map[string]string{
		"hmac_key_id":      in.Key.ID,
		"profile_id":       in.ProfileID,
		"principal_id":     in.PrincipalID,
		"endpoint_id":      in.EndpointID,
		"approval_rule_id": in.ApprovalRuleID,
		"method":           in.Method,
		"scheme":           in.Scheme,
		"host":             in.Host,
		"path":             in.Path,
		"auth_binding_id":  in.AuthBindingID,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrHITLFingerprintInvalid, name)
		}
	}
	if len(in.Key.Root) == 0 {
		return fmt.Errorf("%w: hmac root key is required", ErrHITLFingerprintInvalid)
	}
	return nil
}

func normalizeHITLFingerprintHeaders(headers []HITLFingerprintHeader) ([]HITLFingerprintHeader, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	out := make([]HITLFingerprintHeader, 0, len(headers))
	for _, h := range headers {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if name == "" {
			return nil, fmt.Errorf("%w: empty selected fingerprint header name", ErrHITLFingerprintInvalid)
		}
		if isForbiddenHITLFingerprintHeader(name) {
			return nil, fmt.Errorf("%w: header %q must not be used for HITL request fingerprinting", ErrHITLFingerprintInvalid, name)
		}
		values := make([]string, 0, len(h.Values))
		for _, value := range h.Values {
			values = append(values, strings.TrimSpace(value))
		}
		out = append(out, HITLFingerprintHeader{Name: name, Values: values})
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
			writeHITLCanonicalField(&b, "selected_header_value", strings.TrimSpace(value))
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
