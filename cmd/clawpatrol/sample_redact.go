package main

import (
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
