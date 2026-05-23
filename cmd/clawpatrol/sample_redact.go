package main

import (
	"strings"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const credentialSampleRedaction = "[REDACTED credential]"

func appendCredentialSecretRedactions(dst []string, sec runtime.Secret) []string {
	// Pre-size dst when it's empty: a single credential typically
	// contributes Bytes plus Extras worth of secrets and the old
	// nil-start append chain reallocated up to log2 times. The
	// existing-slice fast path keeps dst as-is so callers can pool
	// the backing array.
	if cap(dst) == 0 {
		dst = make([]string, 0, 1+len(sec.Extras))
	}
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

// redactCredentialSample scrubs every distinct non-empty secret from
// sample, replacing each occurrence with the fixed redaction marker.
//
// Each ReplaceAll runs a Boyer-Moore-ish scan over the sample bytes;
// the early-exit on a sample that doesn't contain the secret (the
// usual case — credentials only show up on the rare-leak paths) bails
// out without allocating. Empty secrets are pre-filtered so they
// don't waste a scan, and a zero-length sample bypasses the loop
// entirely.
//
// Tried a single-pass strings.NewReplacer here for the multi-secret
// hot case: the replacer's per-call trie build allocated more than
// the simple ReplaceAll loop saved, and on the typical
// no-secret-present path the replacer construction was pure waste.
// The straightforward Contains→ReplaceAll loop wins both shapes.
func redactCredentialSample(sample string, secrets []string) string {
	if len(secrets) == 0 || sample == "" {
		return sample
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if !strings.Contains(sample, secret) {
			continue
		}
		sample = strings.ReplaceAll(sample, secret, credentialSampleRedaction)
	}
	return sample
}
