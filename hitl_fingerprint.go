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
	writeHITLCanonicalField(&b, "fingerprint_version", HITLFingerprintVersionV1)
	writeHITLCanonicalField(&b, "profile_id", in.ProfileID)
	writeHITLCanonicalField(&b, "principal_id", in.PrincipalID)
	writeHITLCanonicalField(&b, "endpoint_id", in.EndpointID)
	writeHITLCanonicalField(&b, "approval_rule_id", in.ApprovalRuleID)
	writeHITLCanonicalField(&b, "method", strings.ToUpper(in.Method))
	writeHITLCanonicalField(&b, "scheme", strings.ToLower(in.Scheme))
	writeHITLCanonicalField(&b, "host", strings.ToLower(in.Host))
	writeHITLCanonicalField(&b, "path", in.Path)
	writeHITLCanonicalField(&b, "raw_query", in.RawQuery)
	writeHITLCanonicalField(&b, "selected_header_count", strconv.Itoa(len(in.SelectedHeaders)))
	for _, h := range in.SelectedHeaders {
		writeHITLCanonicalField(&b, "selected_header_name", strings.ToLower(h.Name))
		writeHITLCanonicalField(&b, "selected_header_value_count", strconv.Itoa(len(h.Values)))
		for _, value := range h.Values {
			writeHITLCanonicalField(&b, "selected_header_value", strings.TrimSpace(value))
		}
	}
	writeHITLCanonicalField(&b, "body_hmac", bodyHMAC)
	writeHITLCanonicalField(&b, "auth_binding_id", in.AuthBindingID)
	return b.Bytes()
}

func writeHITLCanonicalField(b *bytes.Buffer, name, value string) {
	b.WriteString(strconv.Itoa(len([]byte(name))))
	b.WriteByte(':')
	b.WriteString(name)
	b.WriteByte('=')
	b.WriteString(strconv.Itoa(len([]byte(value))))
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

func isForbiddenHITLFingerprintHeader(name string) bool {
	name = strings.ToLower(name)
	for _, marker := range []string{"auth", "token", "secret", "key", "password", "cookie"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	switch name {
	case "user-agent",
		"date",
		"x-request-id",
		"traceparent",
		"via",
		"connection",
		"transfer-encoding",
		"accept-encoding":
		return true
	default:
		return strings.HasPrefix(name, "x-b3-")
	}
}
