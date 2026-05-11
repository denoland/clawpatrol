package main

import (
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/denoland/clawpatrol/config/runtime"
)

const (
	bodySampleRedactionMarker = "***"
	binarySamplePreviewBytes  = 64
)

var (
	telegramBotTokenInPath = regexp.MustCompile(`bot\d{6,}:[A-Za-z0-9_-]{20,}`)
	telegramBotTokenBare   = regexp.MustCompile(`\b\d{6,}:[A-Za-z0-9_-]{20,}\b`)
)

type bodySampleRedactor struct {
	needles []string
}

func newBodySampleRedactor() *bodySampleRedactor {
	return &bodySampleRedactor{}
}

func (r *bodySampleRedactor) AddSecret(sec runtime.Secret) {
	r.addSecretBytes(sec.Bytes)
	for _, v := range sec.Extras {
		r.addSecretBytes([]byte(v))
	}
}

func (r *bodySampleRedactor) addSecretBytes(b []byte) {
	if len(b) < 4 {
		return
	}
	raw := string(b)
	r.addNeedle(raw)
	r.addNeedle(hex.EncodeToString(b))
	if escaped := url.QueryEscape(raw); escaped != raw {
		r.addNeedle(escaped)
	}
	if escaped := url.PathEscape(raw); escaped != raw {
		r.addNeedle(escaped)
	}
}

func (r *bodySampleRedactor) addNeedle(needle string) {
	if len(needle) < 4 {
		return
	}
	for _, existing := range r.needles {
		if existing == needle {
			return
		}
	}
	r.needles = append(r.needles, needle)
}

func (r *bodySampleRedactor) Redact(sample string) string {
	if sample == "" {
		return ""
	}
	needles := append([]string(nil), r.needles...)
	sort.SliceStable(needles, func(i, j int) bool {
		return len(needles[i]) > len(needles[j])
	})
	for _, needle := range needles {
		sample = strings.ReplaceAll(sample, needle, bodySampleRedactionMarker)
	}
	sample = telegramBotTokenInPath.ReplaceAllString(sample, "bot"+bodySampleRedactionMarker)
	sample = telegramBotTokenBare.ReplaceAllString(sample, bodySampleRedactionMarker)
	return sample
}

func (r *bodySampleRedactor) RedactStringSample(sample string, truncated bool) string {
	if truncated && len(r.needles) > 0 && sample != "" {
		return bodySampleRedactionMarker
	}
	return r.Redact(sample)
}

func (r *bodySampleRedactor) RedactSample(s *sampler) string {
	if s == nil {
		return ""
	}
	truncated := s.n > int64(s.buf.Len())
	if !truncated && s.buf.Len() > binarySamplePreviewBytes && !isPrintable(s.buf.Bytes()) {
		truncated = true
	}
	return r.RedactStringSample(s.sample(), truncated)
}

func (r *bodySampleRedactor) RedactHeaderMap(headers map[string]string) map[string]string {
	for k, v := range headers {
		if v != bodySampleRedactionMarker {
			headers[k] = r.Redact(v)
		}
	}
	return headers
}
