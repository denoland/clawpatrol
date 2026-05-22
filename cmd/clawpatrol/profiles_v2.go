package main

import (
	"net/http"
	"sort"

	"github.com/denoland/clawpatrol/internal/config"
)

// /api/profiles_v2 backs the dashboard's Profiles list + detail
// surfaces (the V1 Devices page replacement, cl-l6zv).
//
// Without ?name= the handler returns one ProfileSummary per compiled
// profile — just the counts the list-view cards render. With ?name=X
// it returns the full ProfileDetail, including the per-endpoint flow
// data (tunnel chain, rules, credential disambiguators) the detail
// page's flow map needs to draw {endpoint → [tunnel] → rules →
// credential} without re-walking the compiled policy in TypeScript.
//
// Kept separate from the existing /api/profiles (a bare name list
// the device-page profile picker depends on) so consumers don't
// have to pay for the deeper walk when all they need is the picker
// items.

// ProfileSummary is the per-profile counts row rendered as one card
// on the Profiles list page. Devices is the number of agents whose
// onboarded profile matches this profile name.
type ProfileSummary struct {
	Name        string `json:"name"`
	Devices     int    `json:"devices"`
	Endpoints   int    `json:"endpoints"`
	Credentials int    `json:"credentials"`
	Tunnels     int    `json:"tunnels"`
	Rules       int    `json:"rules"`
}

// ProfileTunnelNode is one hop in an endpoint's tunnel chain. The
// chain is rendered outermost-first (the endpoint dials Chain[0],
// which itself rides on Chain[1], and so on); a single-tunnel
// endpoint yields a one-element chain, a direct-dial endpoint
// yields an empty chain.
type ProfileTunnelNode struct {
	Name       string `json:"name"`
	Sharing    string `json:"sharing,omitempty"`
	Credential string `json:"credential,omitempty"`
}

// ProfileRuleSummary mirrors the relevant CompiledRule fields the
// flow map needs to render the per-endpoint rules fan-out + the
// credential each rule resolves to.
type ProfileRuleSummary struct {
	Name       string                `json:"name"`
	Priority   int                   `json:"priority,omitempty"`
	Disabled   bool                  `json:"disabled,omitempty"`
	Condition  string                `json:"condition,omitempty"`
	Credential string                `json:"credential,omitempty"`
	Verdict    string                `json:"verdict,omitempty"`
	Reason     string                `json:"reason,omitempty"`
	Approve    []config.ApproveStage `json:"approve,omitempty"`
}

// ProfileCredentialBinding is one EndpointCredentials entry: the
// credential that may be injected when traffic lands on this
// endpoint, plus the disambiguator key/value pairs the dispatcher
// uses to pick between multiple bindings on the same endpoint.
// Empty Disambiguators marks the catch-all entry (single-credential
// endpoints, or the no-constraint fallback in a multi-credential
// set).
type ProfileCredentialBinding struct {
	Credential     string            `json:"credential"`
	Disambiguators map[string]string `json:"disambiguators,omitempty"`
}

// ProfileEndpoint is the per-endpoint payload the flow map renders.
// Rules are pre-sorted in the same first-match-wins order the
// dispatcher walks them (priority desc, then declaration order).
type ProfileEndpoint struct {
	Name        string                     `json:"name"`
	Family      string                     `json:"family"`
	Hosts       []string                   `json:"hosts,omitempty"`
	TunnelChain []ProfileTunnelNode        `json:"tunnel_chain,omitempty"`
	Rules       []ProfileRuleSummary       `json:"rules,omitempty"`
	Credentials []ProfileCredentialBinding `json:"credentials,omitempty"`
}

// ProfileDetail extends ProfileSummary with the full per-endpoint
// breakdown the detail page renders. The summary fields stay in
// the same shape so the list-view JSON can be embedded inline once
// the operator drills in, without a second round-trip if the list
// payload is still cached.
type ProfileDetail struct {
	ProfileSummary
	Endpoints []ProfileEndpoint `json:"endpoints"`
}

// apiProfilesV2 dispatches between the list view (no name) and the
// detail view (?name=X). Both views read strictly from the loaded
// CompiledPolicy + onboard registry — no DB hits beyond the agent
// snapshot needed for the device count.
func (w *webMux) apiProfilesV2(rw http.ResponseWriter, r *http.Request) {
	policy := w.g.Policy()
	if policy == nil {
		writeJSON(rw, []ProfileSummary{})
		return
	}
	name := r.URL.Query().Get("name")
	devicesByProfile := w.devicesByProfile()
	if name == "" {
		writeJSON(rw, buildProfileSummaries(policy, devicesByProfile, w.g.cfg.Policy))
		return
	}
	prof, ok := policy.Profiles[name]
	if !ok {
		http.Error(rw, "unknown profile: "+name, http.StatusNotFound)
		return
	}
	writeJSON(rw, buildProfileDetail(name, prof, policy, devicesByProfile[name]))
}

// devicesByProfile counts onboarded agents bucketed by their
// assigned profile. Agents with no profile fall under "" and are
// not exposed (the Profiles page only counts agents that resolve
// to one of the declared profiles).
func (w *webMux) devicesByProfile() map[string]int {
	out := map[string]int{}
	if w.g.agents == nil || w.g.onboard == nil {
		return out
	}
	for _, a := range w.g.agents.snapshot() {
		p := w.g.onboard.ProfileForIP(a.IP)
		if p == "" {
			continue
		}
		out[p]++
	}
	return out
}

func buildProfileSummaries(
	policy *config.CompiledPolicy,
	devicesByProfile map[string]int,
	rawPolicy *config.Policy,
) []ProfileSummary {
	names := orderedProfileNames(rawPolicy)
	out := make([]ProfileSummary, 0, len(names))
	for _, n := range names {
		prof, ok := policy.Profiles[n]
		if !ok {
			continue
		}
		out = append(out, summarizeProfile(n, prof, devicesByProfile[n]))
	}
	return out
}

// summarizeProfile counts each entity the profile carries. Tunnels
// dedup across endpoints that share a chain; rules dedup across
// endpoints (a `rule "x"` attached to N endpoints is one declared
// rule). Credentials count the union of profile-declared + tunnel-
// attached entries (mirrors credentialsInProfile so the card's
// "credentials" count matches the credentials section on the detail
// page below).
func summarizeProfile(name string, prof *config.CompiledProfile, devices int) ProfileSummary {
	out := ProfileSummary{Name: name, Devices: devices}
	out.Endpoints = len(prof.Endpoints)
	credSet := profileCredentialSet(prof)
	out.Credentials = len(credSet)
	tunnels := map[string]bool{}
	rules := map[string]bool{}
	for _, ep := range prof.Endpoints {
		for tun := ep.Tunnel; tun != nil; tun = tun.Via {
			tunnels[tun.Name] = true
		}
		for _, r := range ep.Rules {
			rules[r.Name] = true
		}
	}
	out.Tunnels = len(tunnels)
	out.Rules = len(rules)
	return out
}

// profileCredentialSet mirrors credentialsInProfile (agents.go) but
// is package-internal so the buildProfileDetail walk doesn't need a
// non-nil policy + profile-name round-trip. Returns the union of
// the profile's own `credentials = [...]` list and the credentials
// attached to any tunnel reached via one of the profile's endpoints.
func profileCredentialSet(prof *config.CompiledProfile) map[string]bool {
	out := map[string]bool{}
	if prof == nil {
		return out
	}
	for _, ent := range prof.Credentials {
		if ent != nil && ent.Symbol != nil {
			out[ent.Symbol.Name] = true
		}
	}
	for _, ep := range prof.Endpoints {
		for tun := ep.Tunnel; tun != nil; tun = tun.Via {
			if tun.Credential != nil && tun.Credential.Symbol != nil {
				out[tun.Credential.Symbol.Name] = true
			}
		}
	}
	return out
}

func buildProfileDetail(
	name string,
	prof *config.CompiledProfile,
	_ *config.CompiledPolicy,
	devices int,
) ProfileDetail {
	out := ProfileDetail{ProfileSummary: summarizeProfile(name, prof, devices)}
	epNames := make([]string, 0, len(prof.Endpoints))
	for n := range prof.Endpoints {
		epNames = append(epNames, n)
	}
	sort.Strings(epNames)
	for _, epName := range epNames {
		ep := prof.Endpoints[epName]
		out.Endpoints = append(out.Endpoints, buildProfileEndpoint(epName, ep, prof))
	}
	return out
}

func buildProfileEndpoint(name string, ep *config.CompiledEndpoint, prof *config.CompiledProfile) ProfileEndpoint {
	out := ProfileEndpoint{
		Name:   name,
		Family: ep.Family,
		Hosts:  append([]string(nil), ep.Hosts...),
	}
	for tun := ep.Tunnel; tun != nil; tun = tun.Via {
		node := ProfileTunnelNode{Name: tun.Name, Sharing: tun.Sharing}
		if tun.Credential != nil && tun.Credential.Symbol != nil {
			node.Credential = tun.Credential.Symbol.Name
		}
		out.TunnelChain = append(out.TunnelChain, node)
	}
	for _, r := range ep.Rules {
		out.Rules = append(out.Rules, ProfileRuleSummary{
			Name:       r.Name,
			Priority:   r.Priority,
			Disabled:   r.Disabled,
			Condition:  r.Condition,
			Credential: r.Credential,
			Verdict:    r.Outcome.Verdict,
			Reason:     r.Outcome.Reason,
			Approve:    r.Outcome.Approve,
		})
	}
	for _, cc := range prof.EndpointCredentials[name] {
		if cc == nil || cc.Credential == nil || cc.Credential.Symbol == nil {
			continue
		}
		binding := ProfileCredentialBinding{Credential: cc.Credential.Symbol.Name}
		if len(cc.Disambiguators) > 0 {
			binding.Disambiguators = make(map[string]string, len(cc.Disambiguators))
			for k, v := range cc.Disambiguators {
				binding.Disambiguators[k] = v
			}
		}
		out.Credentials = append(out.Credentials, binding)
	}
	// Stable rendering order: catch-all (no disambiguators) last, so
	// the flow map always draws the discriminated branches first and
	// the fallback edge on the bottom row regardless of map iteration.
	sort.SliceStable(out.Credentials, func(i, j int) bool {
		a, b := out.Credentials[i], out.Credentials[j]
		if (len(a.Disambiguators) == 0) != (len(b.Disambiguators) == 0) {
			return len(a.Disambiguators) > 0
		}
		return a.Credential < b.Credential
	})
	return out
}
