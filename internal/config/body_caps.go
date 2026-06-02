package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

const (
	// DefaultRulesEngineBodyCap is the fallback for
	// gateway.body_caps.rules_engine: the most request/response body the
	// gateway buffers before handing it to the rules engine. 1 MiB
	// preserves the historical hardcoded maxHTTPMatchBody value.
	DefaultRulesEngineBodyCap int64 = 1 << 20

	// DefaultActionsTableBodyCap is the fallback for
	// gateway.body_caps.actions_table: the most body the gateway keeps
	// when persisting an action's request/response sample to the audit
	// log. 4 KiB preserves the historical hardcoded sampler cap.
	DefaultActionsTableBodyCap int64 = 4096
)

// BodyCapsBlock is the optional `body_caps { ... }` sub-block inside
// `gateway { ... }`. It exposes the two independent body-size limits as
// human-readable size strings (e.g. "256KiB", "1MiB"):
//
//   - RulesEngine bounds the hot-path buffer the rules engine matches
//     against. Trade-off: latency / memory vs. how much body rules see.
//   - ActionsTable bounds the cold-storage sample persisted per action.
//     Trade-off: disk / db size vs. how useful the action details page
//     is for debugging.
//
// Both are independent: a deployment may log more (or less) than it
// rule-matches. Empty fields fall back to the Default*BodyCap constants,
// which equal today's hardcoded behavior.
type BodyCapsBlock struct {
	RulesEngine  string `hcl:"rules_engine,optional"`
	ActionsTable string `hcl:"actions_table,optional"`
}

// ParseSize parses a human-readable byte-size string into a count of
// bytes. It accepts an optional unit suffix (case-insensitive): bare /
// "B" = bytes, "KiB"/"K", "MiB"/"M", "GiB"/"G" — all binary (1 KiB =
// 1024 bytes). A bare integer is interpreted as bytes. Zero and
// negative values are rejected.
func ParseSize(s string) (int64, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("empty size string")
	}
	// Split the leading (optionally signed) integer from the unit.
	i := 0
	if i < len(trimmed) && (trimmed[i] == '+' || trimmed[i] == '-') {
		i++
	}
	for i < len(trimmed) && trimmed[i] >= '0' && trimmed[i] <= '9' {
		i++
	}
	numPart := trimmed[:i]
	unit := strings.TrimSpace(trimmed[i:])
	if numPart == "" || numPart == "+" || numPart == "-" {
		return 0, fmt.Errorf("size %q has no numeric value", s)
	}
	n, err := strconv.ParseInt(numPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", s, err)
	}
	var mult int64
	switch strings.ToLower(unit) {
	case "", "b":
		mult = 1
	case "k", "kib":
		mult = 1 << 10
	case "m", "mib":
		mult = 1 << 20
	case "g", "gib":
		mult = 1 << 30
	default:
		return 0, fmt.Errorf("size %q: unknown unit %q (use B, KiB, MiB, or GiB)", s, unit)
	}
	bytes := n * mult
	if bytes <= 0 {
		return 0, fmt.Errorf("size %q must be positive", s)
	}
	return bytes, nil
}

// RulesEngineBodyCapFromString parses the rules-engine cap, falling back
// to DefaultRulesEngineBodyCap when the string is empty.
func RulesEngineBodyCapFromString(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return DefaultRulesEngineBodyCap, nil
	}
	return ParseSize(s)
}

// ActionsTableBodyCapFromString parses the actions-table cap, falling
// back to DefaultActionsTableBodyCap when the string is empty.
func ActionsTableBodyCapFromString(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return DefaultActionsTableBodyCap, nil
	}
	return ParseSize(s)
}

// RulesEngineBodyCap returns the configured rules-engine body cap in
// bytes, or DefaultRulesEngineBodyCap when unset/unparseable. Bad input
// is surfaced as a load-time error by validateOperational; this runtime
// accessor falls back to the default so a degraded config still serves.
func (g *Gateway) RulesEngineBodyCap() int {
	bc := g.settings().BodyCaps
	if bc == nil {
		return int(DefaultRulesEngineBodyCap)
	}
	n, err := RulesEngineBodyCapFromString(bc.RulesEngine)
	if err != nil {
		return int(DefaultRulesEngineBodyCap)
	}
	return int(n)
}

// ActionsTableBodyCap returns the configured actions-table body cap in
// bytes, or DefaultActionsTableBodyCap when unset/unparseable.
func (g *Gateway) ActionsTableBodyCap() int {
	bc := g.settings().BodyCaps
	if bc == nil {
		return int(DefaultActionsTableBodyCap)
	}
	n, err := ActionsTableBodyCapFromString(bc.ActionsTable)
	if err != nil {
		return int(DefaultActionsTableBodyCap)
	}
	return int(n)
}

// validateBodyCaps surfaces parse errors at config load time and emits a
// soft warning when the rules-engine cap is smaller than the
// actions-table cap. The inverse is NOT rejected: a deployment may
// deliberately log more than it rule-matches.
func validateBodyCaps(bc *BodyCapsBlock) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if bc == nil {
		return diags
	}
	rules, rErr := RulesEngineBodyCapFromString(bc.RulesEngine)
	if rErr != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid body_caps.rules_engine",
			Detail:   fmt.Sprintf("rules_engine = %q: %v. Use a size string like \"256KiB\" or \"1MiB\".", bc.RulesEngine, rErr),
		})
	}
	actions, aErr := ActionsTableBodyCapFromString(bc.ActionsTable)
	if aErr != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid body_caps.actions_table",
			Detail:   fmt.Sprintf("actions_table = %q: %v. Use a size string like \"64KiB\" or \"256KiB\".", bc.ActionsTable, aErr),
		})
	}
	if rErr == nil && aErr == nil && rules < actions {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagWarning,
			Summary:  "body_caps.rules_engine smaller than actions_table",
			Detail: fmt.Sprintf(
				"rules_engine = %d bytes < actions_table = %d bytes. The rules engine will see less body than is persisted to the actions table. This is allowed, but usually the rules cap is the larger of the two.",
				rules, actions,
			),
		})
	}
	return diags
}
