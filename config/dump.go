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
	if g.LogPath != "" {
		out["log_path"] = g.LogPath
	}
	if g.Resolver != "" {
		out["resolver"] = g.Resolver
	}
	if g.SessionKeep != "" {
		out["session_keep"] = g.SessionKeep
	}
	dumpJoinFields(g, out)
	dumpDefaultsFields(g, out)
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

func dumpJoinFields(g *Gateway, out map[string]any) {
	setStr := func(name, v string) {
		if v != "" {
			out[name] = v
		}
	}
	setStr("authkey", g.AuthKey)
	setStr("control_url", g.ControlURL)
	setStr("hostname", g.Hostname)
	setStr("state_dir", g.StateDir)
	setStr("control", g.Control)
	setStr("oauth_client_id", g.OAuthClientID)
	setStr("oauth_client_secret", g.OAuthClientSecret)
	if len(g.TailscaleTags) > 0 {
		out["tailscale_tags"] = g.TailscaleTags
	}
	setStr("wg_interface", g.WGInterface)
	setStr("wg_endpoint", g.WGEndpoint)
	setStr("wg_server_pub", g.WGServerPub)
	setStr("wg_subnet_cidr", g.WGSubnetCIDR)
}

func dumpDefaultsFields(g *Gateway, out map[string]any) {
	if g.UnknownHost != "" {
		out["unknown_host"] = g.UnknownHost
	}
	if g.LLMFailMode != "" {
		out["llm_fail_mode"] = g.LLMFailMode
	}
	if g.LLMCacheTTL != 0 {
		out["llm_cache_ttl"] = g.LLMCacheTTL
	}
	if g.HumanTimeout != 0 {
		out["human_timeout"] = g.HumanTimeout
	}
	if g.HumanOnTimeout != "" {
		out["human_on_timeout"] = g.HumanOnTimeout
	}
}

func dumpPolicy(p *Policy) map[string]any {
	out := map[string]any{}
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

func dumpEntityMap(m map[string]*Entity) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for name, ent := range m {
		row := map[string]any{}
		// One-label kinds (rule) carry an empty Plugin.Type — the
		// block header has no type label to dump. Family lives on
		// the built body (rules infer it from their endpoints) and
		// gets serialized there.
		if ent.Plugin.Type != "" {
			row["type"] = ent.Plugin.Type
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
