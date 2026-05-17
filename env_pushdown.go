package main

// Runtime substitution for operator-declared env_pushdown { } entries.
// The dashboard hands each agent a unique placeholder per declared
// env var; this file owns the swap-on-outbound-HTTP path that
// replaces the placeholder bytes with the real secret resolved from
// the secret store, so the real secret never leaves the gateway in
// the agent's process environment.
//
// Sibling code:
//   config/env_pushdown.go    HCL schema + placeholder format
//   web.go                    /api/env-pushdown response shape
//   integrations.go           CLI-side env / run pushdown plumbing

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/denoland/clawpatrol/config"
)

// envPushdownSubs returns the (placeholder, secret-name) pairs the
// gateway will swap on outbound HTTP traffic for the active policy.
// Empty when no SecretRef-form env_pushdown entries are declared.
// Pulled into a small helper so the URL / header / body paths can
// share the lazy-resolution closure and the matching loop.
type envPushdownSub struct {
	placeholder string
	secretName  string
}

func (g *Gateway) envPushdownSubs() []envPushdownSub {
	policy := g.Policy()
	if policy == nil || len(policy.EnvPushdown) == 0 {
		return nil
	}
	var subs []envPushdownSub
	for _, e := range policy.EnvPushdown {
		if !e.IsSecret() {
			continue
		}
		subs = append(subs, envPushdownSub{placeholder: e.Placeholder(), secretName: e.SecretRef})
	}
	return subs
}

// applyEnvPushdownURLHeaders rewrites placeholder bytes that
// operator-declared env_pushdown { secret = ... } entries put into
// the agent's environment, swapping each occurrence in URL.Path /
// URL.RawQuery / headers with the real secret resolved from the
// gateway's secret store. The body substitution is split into a
// separate pass (applyEnvPushdownBody) so callers can wrap the body
// sampler around the pre-substitution body before swapping.
//
// Profile is the agent's compiled-policy profile; passed to the
// secret store as the owner key. Resolution errors and missing
// secrets are logged WITHOUT the placeholder / secret bytes (just
// the env var name + profile) so noisy debug output can't be
// weaponized to read the placeholder→credential mapping out of the
// gateway's log stream.
func (g *Gateway) applyEnvPushdownURLHeaders(req *http.Request, profile string) {
	if req == nil {
		return
	}
	subs := g.envPushdownSubs()
	if len(subs) == 0 {
		return
	}
	resolve := g.envPushdownResolver(profile)

	for k, vs := range req.Header {
		for _, s := range subs {
			if !headerListContains(vs, s.placeholder) {
				continue
			}
			realBytes := resolve(s.secretName)
			if len(realBytes) == 0 {
				continue
			}
			for i, v := range vs {
				if !strings.Contains(v, s.placeholder) {
					continue
				}
				vs[i] = strings.ReplaceAll(v, s.placeholder, string(realBytes))
			}
		}
		req.Header[k] = vs
	}

	if req.URL != nil {
		for _, s := range subs {
			if strings.Contains(req.URL.Path, s.placeholder) {
				realBytes := resolve(s.secretName)
				if len(realBytes) > 0 {
					req.URL.Path = strings.ReplaceAll(req.URL.Path, s.placeholder, string(realBytes))
					req.URL.RawPath = ""
				}
			}
			if strings.Contains(req.URL.RawQuery, s.placeholder) {
				realBytes := resolve(s.secretName)
				if len(realBytes) > 0 {
					req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, s.placeholder, string(realBytes))
				}
			}
		}
	}
}

// applyEnvPushdownBody buffers req.Body, swaps placeholder
// occurrences for the resolved real secret bytes, and re-attaches a
// new reader. The body is buffered fully (capped at
// envPushdownBodyMaxBytes); reads past the cap stream through
// unbuffered and the placeholder won't get substituted. Cap matches
// the existing bufferHTTPBodyForMatch limit so we don't introduce a
// second size class with subtly different cutoff behaviour.
//
// Returns true when substitution actually happened. Callers run this
// AFTER wrapping the body sampler so the sampler captures the pre-
// substitution bytes — otherwise the dashboard's request-body sample
// would surface the real secret bytes we just swapped in.
func (g *Gateway) applyEnvPushdownBody(req *http.Request, profile string) bool {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return false
	}
	subs := g.envPushdownSubs()
	if len(subs) == 0 {
		return false
	}
	buf, ok := bufferEnvPushdownBody(req)
	if !ok || len(buf) == 0 {
		return false
	}
	resolve := g.envPushdownResolver(profile)
	changed := false
	for _, s := range subs {
		if !bytes.Contains(buf, []byte(s.placeholder)) {
			continue
		}
		realBytes := resolve(s.secretName)
		if len(realBytes) == 0 {
			continue
		}
		buf = bytes.ReplaceAll(buf, []byte(s.placeholder), realBytes)
		changed = true
	}
	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.ContentLength = int64(len(buf))
	return changed
}

// envPushdownResolver returns a memoising closure that looks up an
// env_pushdown SecretRef in the gateway's secret store, keyed on
// the agent's profile. Cache hits because a single request can
// reference the same placeholder several times (multipart forms,
// repeating JSON fields). Logging deliberately omits secret bytes /
// placeholder bytes — only the env var name and profile are emitted.
func (g *Gateway) envPushdownResolver(profile string) func(string) []byte {
	cache := map[string][]byte{}
	return func(name string) []byte {
		if v, ok := cache[name]; ok {
			return v
		}
		sec, err := g.secrets.Get(name)
		if err != nil {
			log.Printf("env_pushdown %s/%s: secret lookup failed (forwarding placeholder verbatim)", name, profile)
			cache[name] = nil
			return nil
		}
		if len(sec.Bytes) == 0 {
			log.Printf("env_pushdown %s/%s: secret not configured (set CLAWPATROL_SECRET_%s)", name, profile, secretEnvName(name))
			cache[name] = nil
			return nil
		}
		cache[name] = sec.Bytes
		return sec.Bytes
	}
}

// envPushdownBodyMaxBytes caps how much body we'll buffer for
// placeholder substitution. Matches the existing match-buffering
// cap so operators don't have to reason about two different sizes;
// reads past the cap stream through unbuffered (no substitution).
// 1 MiB is enough for every agent CLI request shape we've observed
// (chat completion JSON, codex/ChatGPT response bodies are bigger
// but flow inbound, not outbound).
const envPushdownBodyMaxBytes = 1 << 20

// bufferEnvPushdownBody reads up to envPushdownBodyMaxBytes off
// req.Body. Returns (buf, true) on success — caller is responsible
// for resetting req.Body to a fresh reader. Returns (nil, false)
// when the body would exceed the cap; the caller leaves the
// original Body untouched.
func bufferEnvPushdownBody(req *http.Request) ([]byte, bool) {
	body := req.Body
	defer func() { _ = body.Close() }()
	lim := io.LimitReader(body, envPushdownBodyMaxBytes+1)
	buf, err := io.ReadAll(lim)
	if err != nil {
		return nil, false
	}
	if len(buf) > envPushdownBodyMaxBytes {
		// Body was larger than the cap; replace req.Body with a
		// MultiReader so the upstream still gets the full payload,
		// but skip substitution.
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), body))
		return nil, false
	}
	return buf, true
}

func headerListContains(vs []string, needle string) bool {
	for _, v := range vs {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

// envPushdownPlaceholders returns the full list of placeholder
// strings the gateway hands out for the operator's SecretRef-form
// env_pushdown declarations. Used by the response sanitizer to
// scrub placeholder bytes that — defensively — might appear in an
// upstream response (a misbehaving upstream echoing the auth slot).
// Returns nil when no env_pushdown entries are declared.
func envPushdownPlaceholders(policy *config.CompiledPolicy) []string {
	if policy == nil || len(policy.EnvPushdown) == 0 {
		return nil
	}
	out := make([]string, 0, len(policy.EnvPushdown))
	for _, e := range policy.EnvPushdown {
		if !e.IsSecret() {
			continue
		}
		out = append(out, e.Placeholder())
	}
	return out
}
