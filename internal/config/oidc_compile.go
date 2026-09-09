package config

import (
	"fmt"
	"sort"
	"time"
)

func compileOIDCEnrollments(cp *CompiledPolicy, p *Policy, publicURL string) error {
	if cp == nil || p == nil || len(p.Enrollments) == 0 {
		return nil
	}
	audience, err := NormalizePublicURLForOIDC(publicURL)
	if err != nil {
		return fmt.Errorf("oidc enrollment audience: %w", err)
	}
	cp.OIDCAudience = audience
	ordered := orderedEnrollmentNames(p)
	for _, name := range ordered {
		ent := p.Enrollments[name]
		if ent == nil {
			continue
		}
		oe, ok := ent.Body.(*OIDCEnrollment)
		if !ok {
			return fmt.Errorf("oidc enrollment %q: unexpected body %T", name, ent.Body)
		}
		profile := cp.Profiles[oe.Profile]
		if profile == nil {
			return fmt.Errorf("oidc enrollment %q: profile %q not compiled", name, oe.Profile)
		}
		ttl, err := time.ParseDuration(oe.TTL)
		if err != nil {
			return fmt.Errorf("oidc enrollment %q ttl: %w", name, err)
		}
		maxTTL, err := time.ParseDuration(oe.MaxTTL)
		if err != nil {
			return fmt.Errorf("oidc enrollment %q max_ttl: %w", name, err)
		}
		compiled := &CompiledOIDCEnrollment{
			Name:     name,
			Issuer:   oe.Issuer,
			Profile:  profile,
			TTL:      ttl,
			MaxTTL:   maxTTL,
			Match:    cloneAnyMap(oe.Match),
			Metadata: cloneAnyMap(oe.Metadata),
		}
		cp.OIDCEnrollments = append(cp.OIDCEnrollments, compiled)
		cp.OIDCEnrollmentsByIssuer[compiled.Issuer] = append(cp.OIDCEnrollmentsByIssuer[compiled.Issuer], compiled)
	}
	return nil
}

func orderedEnrollmentNames(p *Policy) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range p.Order {
		if _, ok := p.Enrollments[name]; ok && !seen[name] {
			out = append(out, name)
			seen[name] = true
		}
	}
	if len(out) == len(p.Enrollments) {
		return out
	}
	var rest []string
	for name := range p.Enrollments {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch vv := v.(type) {
		case []string:
			out[k] = append([]string(nil), vv...)
		case []any:
			out[k] = append([]any(nil), vv...)
		default:
			out[k] = vv
		}
	}
	return out
}
