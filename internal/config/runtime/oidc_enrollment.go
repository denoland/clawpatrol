package runtime

import (
	"fmt"
	"reflect"

	"github.com/denoland/clawpatrol/internal/config"
)

// MatchOIDCEnrollment matches already-verified OIDC claims against compiled
// enrollment policy. It never falls back to a default profile: enrollment is an
// explicit profile grant, unlike endpoint dispatch's single-tenant fallback.
func MatchOIDCEnrollment(policy *config.CompiledPolicy, req *config.OIDCClaimRequest) (*config.CompiledOIDCEnrollment, *config.CompiledProfile, error) {
	if policy == nil || req == nil {
		return nil, nil, nil
	}
	if !audienceMatches(policy.OIDCAudience, req.Audience, req.AuthorizedParty) {
		return nil, nil, nil
	}
	candidates := policy.OIDCEnrollmentsByIssuer[req.Issuer]
	var matches []*config.CompiledOIDCEnrollment
	for _, enr := range candidates {
		if enr == nil || enr.Profile == nil || !enr.Profile.AllowEphemeralOIDC {
			continue
		}
		if claimMapMatches(enr.Match, req.Claims) {
			matches = append(matches, enr)
		}
	}
	switch len(matches) {
	case 0:
		return nil, nil, nil
	case 1:
		return matches[0], matches[0].Profile, nil
	default:
		return nil, nil, fmt.Errorf("ambiguous OIDC enrollment match for issuer %q", req.Issuer)
	}
}

func audienceMatches(want string, audiences []string, azp string) bool {
	if want == "" || len(audiences) == 0 {
		return false
	}
	found := false
	for _, aud := range audiences {
		if aud == want {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if len(audiences) > 1 && azp != want {
		return false
	}
	return true
}

func claimMapMatches(match map[string]any, claims map[string]any) bool {
	if len(match) == 0 {
		return false
	}
	for key, want := range match {
		got, ok := claims[key]
		if !ok || !claimValueMatches(want, got) {
			return false
		}
	}
	return true
}

func claimValueMatches(want any, got any) bool {
	wantStrings, wantIsList := scalarStringList(want)
	gotStrings, gotIsList := scalarStringList(got)
	if wantIsList {
		if gotIsList {
			for _, g := range gotStrings {
				if stringInSet(g, wantStrings) {
					return true
				}
			}
			return false
		}
		gotString, ok := got.(string)
		return ok && stringInSet(gotString, wantStrings)
	}
	if gotIsList {
		wantString, ok := want.(string)
		return ok && stringInSet(wantString, gotStrings)
	}
	return reflect.DeepEqual(want, got)
}

func scalarStringList(v any) ([]string, bool) {
	switch vv := v.(type) {
	case []string:
		return vv, true
	case []any:
		out := make([]string, 0, len(vv))
		for _, elem := range vv {
			out = append(out, fmt.Sprint(elem))
		}
		return out, true
	default:
		return nil, false
	}
}

func stringInSet(s string, set []string) bool {
	for _, item := range set {
		if item == s {
			return true
		}
	}
	return false
}
