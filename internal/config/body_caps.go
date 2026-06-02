package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Body-cap defaults preserve the gateway's historical hardcoded
// behavior so configs that omit `gateway.body_caps` load unchanged.
const (
	// DefaultRulesEngineBodyCap is how much of a request body the
	// gateway buffers before handing it to the rules engine
	// (runtime.MatchRequest). Mirrors the old maxHTTPMatchBody
	// constant: 1 MiB. Hot path — every body-bearing request reads up
	// to this much before a rule can see it.
	DefaultRulesEngineBodyCap int64 = 1 << 20 // 1 MiB

	// DefaultActionsTableBodyCap is how much of each request/response
	// body the gateway persists in the actions audit table. Mirrors the
	// old newSampler(4096) call: 4 KiB. Cold storage — trades disk/db
	// size against how useful the action-details page is for debugging.
	DefaultActionsTableBodyCap int64 = 4 << 10 // 4 KiB
)

// BodyCaps is the body of the optional `body_caps { ... }` sub-block
// inside `gateway { ... }`. It exposes two independent caps because
// their concerns differ: the rules-engine cap governs a per-request
// hot-path buffer (latency / memory vs. how much body rules can match
// on), while the actions-table cap governs cold per-action storage
// (disk / db size vs. debuggability of the action-details page).
//
// Both fields accept human-readable size strings ("256KiB", "1MiB",
// "4096"); empty falls back to the matching Default*BodyCap. See
// ParseSize for the accepted grammar.
type BodyCaps struct {
	// RulesEngine caps the request body buffered before MatchRequest.
	// Empty → DefaultRulesEngineBodyCap (1 MiB).
	RulesEngine string `hcl:"rules_engine,optional"`

	// ActionsTable caps the request/response body persisted per action.
	// Empty → DefaultActionsTableBodyCap (4 KiB).
	ActionsTable string `hcl:"actions_table,optional"`
}

// ParseSize parses a human-readable binary size string into a byte
// count. Accepted forms (case-insensitive, surrounding whitespace
// trimmed):
//
//	"1024"        → 1024 bytes (a bare number is bytes)
//	"512B"        → 512 bytes
//	"256KiB"      → 256 * 1024
//	"4MiB"        → 4 * 1024 * 1024
//	"2GiB"        → 2 * 1024 * 1024 * 1024
//
// Units are binary (powers of 1024). The result must be positive:
// zero and negative values are rejected, as is a missing/empty input,
// an unrecognised unit, or a non-numeric magnitude.
func ParseSize(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("empty size")
	}

	// Split the trailing unit (letters) from the leading magnitude.
	num := raw
	unit := ""
	for i := len(raw) - 1; i >= 0; i-- {
		c := raw[i]
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' {
			num = strings.TrimSpace(raw[:i+1])
			unit = strings.TrimSpace(raw[i+1:])
			break
		}
		if i == 0 {
			// All letters, no magnitude (e.g. "KiB").
			return 0, fmt.Errorf("missing size magnitude in %q", s)
		}
	}

	var mult int64
	switch strings.ToLower(unit) {
	case "", "b":
		mult = 1
	case "k", "kib", "kb":
		mult = 1 << 10
	case "m", "mib", "mb":
		mult = 1 << 20
	case "g", "gib", "gb":
		mult = 1 << 30
	default:
		return 0, fmt.Errorf("unknown size unit %q in %q (use B/KiB/MiB/GiB)", unit, s)
	}

	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size magnitude %q in %q: %w", num, s, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("size must be positive, got %q", s)
	}
	if n > (1<<63-1)/mult {
		return 0, fmt.Errorf("size %q overflows int64", s)
	}
	return n * mult, nil
}

// bodyCapFromString resolves an optional size-string field to a byte
// count, falling back to def when the string is empty. A non-empty but
// malformed string returns an error — validateOperational surfaces it
// at load time; the runtime accessors treat the error as "use the
// default" so a bad value degrades to historical behavior rather than
// crashing a live gateway on reload.
func bodyCapFromString(s string, def int64) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return ParseSize(s)
}

// bodyCaps returns the configured `body_caps` block, or nil when the
// gateway block omits it.
func (g *Gateway) bodyCaps() *BodyCaps {
	if g == nil || g.Settings == nil {
		return nil
	}
	return g.Settings.BodyCaps
}

// RulesEngineBodyCap returns the resolved rules-engine body buffer cap
// in bytes, falling back to DefaultRulesEngineBodyCap when unset or
// malformed. Read on the request hot path.
func (g *Gateway) RulesEngineBodyCap() int64 {
	bc := g.bodyCaps()
	if bc == nil {
		return DefaultRulesEngineBodyCap
	}
	n, err := bodyCapFromString(bc.RulesEngine, DefaultRulesEngineBodyCap)
	if err != nil {
		return DefaultRulesEngineBodyCap
	}
	return n
}

// ActionsTableBodyCap returns the resolved actions-table body cap in
// bytes, falling back to DefaultActionsTableBodyCap when unset or
// malformed. Read at action-persistence time.
func (g *Gateway) ActionsTableBodyCap() int64 {
	bc := g.bodyCaps()
	if bc == nil {
		return DefaultActionsTableBodyCap
	}
	n, err := bodyCapFromString(bc.ActionsTable, DefaultActionsTableBodyCap)
	if err != nil {
		return DefaultActionsTableBodyCap
	}
	return n
}
