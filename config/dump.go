package config

import (
	"bytes"
	"encoding/json"
)

// Dump renders the loaded gateway as deterministic, indented JSON for
// golden-file tests. Maps marshal in sorted-key order; entity bodies
// are produced by plugin Build functions and are expected to be
// json-friendly (no cty.Value fields).
//
// The output is NOT a stable serialization format. It changes when
// schema or plugins evolve and goldens regenerate via -update.
func (g *Gateway) Dump() ([]byte, error) {
	out := map[string]any{}
	if g.Listen != "" {
		out["listen"] = g.Listen
	}
	if g.InfoListen != "" {
		out["info_listen"] = g.InfoListen
	}
	if g.PublicURL != "" {
		out["public_url"] = g.PublicURL
	}
	if g.AdminEmail != "" {
		out["admin_email"] = g.AdminEmail
	}
	if g.CADir != "" {
		out["ca_dir"] = g.CADir
	}
	if g.LogPath != "" {
		out["log_path"] = g.LogPath
	}
	if g.OAuthDir != "" {
		out["oauth_dir"] = g.OAuthDir
	}
	if g.Resolver != "" {
		out["resolver"] = g.Resolver
	}
	if g.Tailscale != nil && !isZeroTailscale(g.Tailscale) {
		out["gateway"] = g.Tailscale
	}
	if g.Policy != nil {
		out["policy"] = dumpPolicy(g.Policy)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isZeroTailscale(t *Tailscale) bool {
	return t.AuthKey == "" && t.ControlURL == "" && t.Hostname == "" &&
		t.StateDir == "" && t.Control == "" && t.OAuthClientID == "" &&
		t.OAuthClientSecret == "" && len(t.Tags) == 0 &&
		t.WGInterface == "" && t.WGEndpoint == "" && t.WGServerPub == "" &&
		t.WGSubnetCIDR == ""
}

func dumpPolicy(p *Policy) map[string]any {
	out := map[string]any{}
	if d := dumpDefaults(p.Defaults); d != nil {
		out["defaults"] = d
	}
	if v := dumpEntityMap(p.Approvers); v != nil {
		out["approvers"] = v
	}
	if v := dumpPolicies(p.Policies); v != nil {
		out["policies"] = v
	}
	if v := dumpEntityMap(p.Credentials); v != nil {
		out["credentials"] = v
	}
	if v := dumpEntityMap(p.Endpoints); v != nil {
		out["endpoints"] = v
	}
	if v := dumpEntityMap(p.Rules); v != nil {
		out["rules"] = v
	}
	if v := dumpEntityMap(p.Tunnels); v != nil {
		out["tunnels"] = v
	}
	if v := dumpProfiles(p.Profiles); v != nil {
		out["profiles"] = v
	}
	return out
}

func dumpDefaults(d Defaults) map[string]any {
	if d == (Defaults{}) {
		return nil
	}
	out := map[string]any{}
	if d.UnknownHost != "" {
		out["unknown_host"] = d.UnknownHost
	}
	if d.LLMFailMode != "" {
		out["llm_fail_mode"] = d.LLMFailMode
	}
	if d.LLMCacheTTL != 0 {
		out["llm_cache_ttl"] = d.LLMCacheTTL
	}
	if d.HumanTimeout != 0 {
		out["human_timeout"] = d.HumanTimeout
	}
	if d.HumanOnTimeout != "" {
		out["human_on_timeout"] = d.HumanOnTimeout
	}
	return out
}

func dumpEntityMap(m map[string]*Entity) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for name, ent := range m {
		row := map[string]any{
			"type": ent.Plugin.Type,
		}
		if ent.Plugin.Family != "" {
			row["family"] = ent.Plugin.Family
		}
		row["body"] = ent.Body
		// Surface framework-level attrs (e.g. tunnel) at the entity
		// row, not inside the plugin body — matches where the
		// loader extracted them from.
		for _, spec := range frameworkAttrsByKind[ent.Symbol.Kind] {
			if v := ent.Framework.Ref(spec.Name); v != "" {
				row[spec.Name] = v
			}
		}
		out[name] = row
	}
	return out
}

func dumpPolicies(m map[string]*PolicyText) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for name, p := range m {
		out[name] = map[string]any{"text": p.Text}
	}
	return out
}

func dumpProfiles(m map[string]*Profile) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for name, p := range m {
		out[name] = map[string]any{"endpoints": p.Endpoints}
	}
	return out
}
