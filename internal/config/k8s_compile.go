package config

import (
	"fmt"
	"time"
)

// CompiledK8sEnrollment is the plugin-owned runtime body for a
// kubernetes_token_review enrollment.
type CompiledK8sEnrollment struct {
	Audience string
	Matches  []CompiledK8sMatch
}

// CompiledK8sMatch is one identity → profile-binding rule.
type CompiledK8sMatch struct {
	Namespace      string
	ServiceAccount string
	ProfileLabel   string
	Profiles       []string
}

func compileK8sEnrollment(body any, name string, profiles map[string]*CompiledProfile) (any, EnrollmentLiveness, error) {
	ke, ok := body.(*K8sEnrollment)
	if !ok {
		return nil, EnrollmentLiveness{}, fmt.Errorf("enrollment %q: unexpected body %T", name, body)
	}
	liveness, err := resolveEnrollmentLiveness(ke.KeepaliveInterval, ke.KeepaliveReapCount)
	if err != nil {
		return nil, EnrollmentLiveness{}, fmt.Errorf("enrollment %q keepalive_interval: %w", name, err)
	}
	compiled := &CompiledK8sEnrollment{Audience: ke.Audience}
	for _, m := range ke.Matches {
		for _, prof := range m.Profiles {
			if _, ok := profiles[prof]; !ok {
				return nil, EnrollmentLiveness{}, fmt.Errorf("enrollment %q: profile %q not compiled", name, prof)
			}
		}
		compiled.Matches = append(compiled.Matches, CompiledK8sMatch{
			Namespace:      m.Namespace,
			ServiceAccount: m.ServiceAccount,
			ProfileLabel:   m.ProfileLabel,
			Profiles:       append([]string(nil), m.Profiles...),
		})
	}
	return compiled, liveness, nil
}

func parseOptionalDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	return time.ParseDuration(raw)
}
