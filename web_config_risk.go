package main

// Risky-tunnel gate for dashboard /api/config/* writes.
//
// `tunnel "local_command" "..." { command = [...] }` spawns an
// arbitrary OS process. Any operator with the dashboard secret can
// POST a new gateway.hcl that introduces such a block and then route
// traffic through it — full RCE on the gateway host (denoland/orchid
// F-4). The configuration preview/save flow runs the HCL through the
// parser, but parsing doesn't catch "this is the first time we've
// seen this command name appear" — that judgment has to live one
// layer up.
//
// This file isolates the type allowlist + new-block detection so the
// rest of web.go doesn't grow a tunnel-specific switch. Two seams:
//
//   * riskyTunnelDiff(current, new) — for the dashboard's
//     preview/save handshake. Returns the names of newly-added risky
//     blocks; the UI surfaces them in a red banner and requires an
//     explicit "confirm_high_risk" before save.
//
//   * disallowedTunnelTypes(policy, allow) — for the --allow-tunnels
//     gateway boot flag. Returns the names of declared tunnels whose
//     plugin type isn't in the allowlist. Empty allowlist = no
//     restriction (preserves current behaviour; protection is
//     opt-in).

import (
	"sort"

	"github.com/denoland/clawpatrol/config"
)

// riskyTunnelTypes lists tunnel plugin types whose HCL fields drive
// arbitrary code execution on the gateway host. Adding a tunnel type
// here makes its dashboard-introduced instances require the
// confirm_high_risk gesture.
var riskyTunnelTypes = map[string]bool{
	"local_command": true,
}

// riskyTunnelDiff returns the names of risky-typed tunnel blocks
// declared in newHCL but not in currentHCL. Returns nil when either
// input is unparseable — validateAndFormatConfig already surfaces the
// parse error, so we don't want to double-report.
func riskyTunnelDiff(currentHCL, newHCL []byte) []string {
	cur := riskyTunnelNames(currentHCL)
	nu := riskyTunnelNames(newHCL)
	if nu == nil {
		return nil
	}
	if cur == nil {
		cur = map[string]bool{}
	}
	var out []string
	for name := range nu {
		if !cur[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// riskyTunnelNames loads the HCL and walks Policy.Tunnels for the
// risky plugin types. Returns nil on parse failure (signal to the
// caller "I can't compute this diff right now"), empty map on
// success when no risky tunnels are declared.
func riskyTunnelNames(hcl []byte) map[string]bool {
	if len(hcl) == 0 {
		return map[string]bool{}
	}
	gw, diags := config.LoadBytes(hcl, "config.hcl")
	if diags.HasErrors() || gw == nil || gw.Policy == nil {
		return nil
	}
	out := map[string]bool{}
	for name, ent := range gw.Policy.Tunnels {
		if ent == nil || ent.Plugin == nil {
			continue
		}
		if riskyTunnelTypes[ent.Plugin.Type] {
			out[name] = true
		}
	}
	return out
}

// disallowedTunnelTypes scans a loaded policy and returns the names
// of tunnel blocks whose plugin type isn't in allow. Empty allow
// (len==0) means "no restriction" — function returns nil.
//
// Used by gateway boot to fail-fast on an HCL that declares tunnel
// types the operator's --allow-tunnels flag excludes, and by the
// dashboard preview to reject saves that would re-introduce them.
func disallowedTunnelTypes(policy *config.Policy, allow map[string]bool) []string {
	if len(allow) == 0 || policy == nil {
		return nil
	}
	var out []string
	for name, ent := range policy.Tunnels {
		if ent == nil || ent.Plugin == nil {
			continue
		}
		if !allow[ent.Plugin.Type] {
			out = append(out, name+" ("+ent.Plugin.Type+")")
		}
	}
	sort.Strings(out)
	return out
}

// disallowedTunnelTypesInHCL parses the given HCL and returns the
// tunnel block names whose plugin type isn't in allow. Returns nil
// when the HCL doesn't parse (validateAndFormatConfig already
// surfaces parse errors), or when allow is empty.
func disallowedTunnelTypesInHCL(hcl []byte, allow map[string]bool) []string {
	if len(allow) == 0 || len(hcl) == 0 {
		return nil
	}
	gw, diags := config.LoadBytes(hcl, "config.hcl")
	if diags.HasErrors() || gw == nil {
		return nil
	}
	return disallowedTunnelTypes(gw.Policy, allow)
}

// parseAllowTunnels turns the comma-separated --allow-tunnels flag
// value into a set. Whitespace around entries is trimmed. Empty input
// returns nil (preserved unrestricted semantics).
func parseAllowTunnels(s string) map[string]bool {
	if s == "" {
		return nil
	}
	out := map[string]bool{}
	for _, raw := range splitAndTrim(s, ',') {
		if raw != "" {
			out[raw] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitAndTrim(s string, sep rune) []string {
	var out []string
	start := 0
	for i, r := range s {
		if r == sep {
			out = append(out, trimASCIISpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimASCIISpace(s[start:]))
	return out
}

func trimASCIISpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 {
		last := s[len(s)-1]
		if last != ' ' && last != '\t' && last != '\n' && last != '\r' {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
