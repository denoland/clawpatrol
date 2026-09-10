package main

import (
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const credentialSampleRedaction = "[REDACTED credential]"

func appendCredentialSecretRedactions(dst []string, sec runtime.Secret) []string {
	dst = appendCredentialSecretRedaction(dst, string(sec.Bytes))
	for _, extra := range sec.Extras {
		dst = appendCredentialSecretRedaction(dst, extra)
	}
	return dst
}

func appendCredentialSecretRedaction(dst []string, secret string) []string {
	if secret == "" {
		return dst
	}
	for _, existing := range dst {
		if existing == secret {
			return dst
		}
	}
	return append(dst, secret)
}

func redactCredentialSample(sample string, secrets []string) string {
	secrets = append([]string(nil), secrets...)
	sort.SliceStable(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		sample = strings.ReplaceAll(sample, secret, credentialSampleRedaction)
	}
	return sample
}

// injectedHeaderSecrets returns the sensitive values a credential put
// on the wire that are not the raw secret: every header value that
// injection or signing added or changed, plus the token part of an
// Authorization-style "<scheme> <token>" value. Basic auth sends a
// base64 of user:password, signers mint tokens or signatures, and an
// upstream that reflects request headers into an error body would
// otherwise persist those verbatim. Values shorter than eight bytes
// are skipped: they are not credentials and would shred samples.
func injectedHeaderSecrets(before, after http.Header) []string {
	var out []string
	for key, vals := range after {
		prev := before[key]
		for _, v := range vals {
			if v == "" || len(v) < 8 || slices.Contains(prev, v) {
				continue
			}
			out = appendCredentialSecretRedaction(out, v)
			if _, tok, ok := strings.Cut(v, " "); ok && len(tok) >= 8 {
				out = appendCredentialSecretRedaction(out, tok)
			}
		}
	}
	return out
}
