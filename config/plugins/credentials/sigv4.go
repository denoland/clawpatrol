package credentials

// SigV4 signing for AWS API requests. Hand-rolled rather than pulling
// aws-sdk-go-v2: PR #228 stripped the SDK from every build via the
// ts_omit_identityfederation build tag (~3 MB + every AWS symbol).
// Reintroducing it for one credential plugin would undo that, so the
// algorithm lives here in ~250 LOC. Verified against the AWS
// canonical test vectors in sigv4_test.go.
//
// Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4-signing.html

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sigV4Params is the per-request input to signSigV4. Caller fills it
// from the endpoint config and the credential's secret material.
type sigV4Params struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional; STS-issued credentials
	Service         string // e.g. "s3", "dynamodb"
	Region          string // e.g. "us-east-1"
	Now             time.Time
}

// signSigV4 stamps the SigV4 headers on req in place: Host (if
// missing), X-Amz-Date, X-Amz-Content-SHA256, optional
// X-Amz-Security-Token, and the final Authorization header. The
// request body is read in full to hash, then restored as an
// in-memory buffer (no streaming SigV4 in v1).
func signSigV4(req *http.Request, p sigV4Params) error {
	if p.AccessKeyID == "" || p.SecretAccessKey == "" {
		return fmt.Errorf("sigv4: missing access_key_id / secret_access_key")
	}
	if p.Service == "" || p.Region == "" {
		return fmt.Errorf("sigv4: missing service / region")
	}
	now := p.Now.UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Body hash. Read fully, restore as buffered body. Streaming
	// SigV4 (UNSIGNED-PAYLOAD / chunked) is out of scope for v1.
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("sigv4: read body: %w", err)
		}
		_ = req.Body.Close()
		bodyBytes = b
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
	}
	payloadHash := hex.EncodeToString(sha256sum(bodyBytes))

	// Canonical headers must include host (the wire host header) and
	// x-amz-date. Strip prior signing-related headers — gateway's
	// signature is authoritative; whatever the agent stamped is
	// replaced.
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Content-Sha256")
	req.Header.Del("X-Amz-Security-Token")

	req.Header.Set("X-Amz-Date", amzDate)
	// X-Amz-Content-Sha256 is mandatory for S3 (and a small set of
	// services like Glacier) and optional elsewhere. AWS SDK v2 only
	// stamps it for those services; sending it on others gratuitously
	// expands SignedHeaders, which is harmless but unnecessary. Match
	// the SDK default so canonical test vectors (which assume the
	// header is absent for non-S3 services) reproduce exactly.
	if requiresContentSHA256(p.Service) {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	if p.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", p.SessionToken)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	canonHeaders, signedHeaders := canonicalHeaders(req.Header, host)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQueryString(req.URL),
		canonHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + p.Region + "/" + p.Service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(sha256sum([]byte(canonicalRequest))),
	}, "\n")

	signingKey := deriveSigningKey(p.SecretAccessKey, dateStamp, p.Region, p.Service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		p.AccessKeyID, scope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", auth)
	return nil
}

// canonicalURI percent-encodes the path per AWS rules. Each path
// segment is URI-encoded independently; '/' separators are preserved.
// Empty path becomes "/". For S3-on-amazonaws the AWS docs allow
// non-normalization, but we don't normalize anyway — the request
// arrived already in the form the agent intended.
func canonicalURI(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	parts := strings.Split(u.Path, "/")
	for i, p := range parts {
		parts[i] = awsURIEncode(p, false)
	}
	return strings.Join(parts, "/")
}

// canonicalQueryString sorts query params by name (then by value for
// repeats) and URI-encodes both name and value per AWS rules.
func canonicalQueryString(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	// url.ParseQuery decodes percent-encoding for us, which means we
	// re-encode below with awsURIEncode (the canonical form may
	// differ from net/url's). Equivalent to the AWS reference impl.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return u.RawQuery // best effort; signature will mismatch upstream
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	first := true
	for _, k := range keys {
		vals := append([]string{}, q[k]...)
		sort.Strings(vals)
		ek := awsURIEncode(k, true)
		for _, v := range vals {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(ek)
			b.WriteByte('=')
			b.WriteString(awsURIEncode(v, true))
		}
	}
	return b.String()
}

// canonicalHeaders returns the canonical-headers block and the
// signed-headers list. Every header in req.Header is signed (plus a
// synthetic host entry); operators can't omit headers — that's an
// AWS-side concern we don't need to expose for the v1 inject path.
func canonicalHeaders(h http.Header, host string) (canonical, signed string) {
	// Map header-name (lower) → joined values (trimmed, comma-sep).
	flat := make(map[string]string, len(h)+1)
	flat["host"] = strings.TrimSpace(host)
	for name, vals := range h {
		lower := strings.ToLower(name)
		joined := make([]string, 0, len(vals))
		for _, v := range vals {
			joined = append(joined, normalizeHeaderValue(v))
		}
		flat[lower] = strings.Join(joined, ",")
	}
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var cb strings.Builder
	for _, k := range keys {
		cb.WriteString(k)
		cb.WriteByte(':')
		cb.WriteString(flat[k])
		cb.WriteByte('\n')
	}
	return cb.String(), strings.Join(keys, ";")
}

// normalizeHeaderValue collapses internal whitespace runs to a single
// space and trims leading/trailing whitespace. Per AWS, quoted
// portions are left alone; we approximate by skipping the
// inside-quotes case (rare in practice).
func normalizeHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	if !strings.ContainsAny(v, "  \t") {
		return v
	}
	var b strings.Builder
	inSpace := false
	for _, r := range v {
		if r == ' ' || r == '\t' {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

// awsURIEncode percent-encodes per the AWS rules: A-Z, a-z, 0-9, '-',
// '_', '.', '~' pass through; '/' passes through only when encodeSlash
// is false (path-segment encoding leaves '/' as a separator, but the
// AWS rules technically also leave it inside *segments* — the spec
// says: never encode '/' in URI paths). Everything else is %XX.
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// requiresContentSHA256 reports whether the service mandates an
// X-Amz-Content-Sha256 header on every request. Currently only S3
// and Glacier; expand as needed. The hash always feeds the canonical
// request regardless — this only governs whether the header is on
// the wire (and therefore in SignedHeaders).
func requiresContentSHA256(service string) bool {
	switch service {
	case "s3", "s3-outposts", "glacier":
		return true
	}
	return false
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256sum(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}
