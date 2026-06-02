package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

const (
	// DefaultBodyBufferLimit is the fallback for
	// gateway.limits.body_buffer: the most request/response body the
	// gateway buffers before handing it to the rules engine. 1 MiB
	// preserves the historical hardcoded maxHTTPMatchBody value.
	DefaultBodyBufferLimit int64 = 1 << 20

	// DefaultBodyStorageLimit is the fallback for
	// gateway.limits.body_storage: the most body the gateway keeps
	// when persisting an action's request/response sample to the audit
	// log. 4 KiB preserves the historical hardcoded sampler cap.
	DefaultBodyStorageLimit int64 = 4096
)

// LimitsBlock is the optional `limits { ... }` sub-block inside
// `gateway { ... }`. It exposes the two independent body-size limits as
// human-readable size strings (e.g. "256KiB", "1MiB"):
//
//   - BodyBuffer bounds the hot-path buffer the rules engine matches
//     against. Trade-off: latency / memory vs. how much body rules see.
//   - BodyStorage bounds the cold-storage sample persisted per action.
//     Trade-off: disk / db size vs. how useful the action details page
//     is for debugging.
//
// Both are independent: a deployment may log more (or less) than it
// rule-matches. Empty fields fall back to the DefaultBody*Limit
// constants, which equal today's hardcoded behavior.
type LimitsBlock struct {
	BodyBuffer  string `hcl:"body_buffer,optional"`
	BodyStorage string `hcl:"body_storage,optional"`
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

// BodyBufferLimitFromString parses the body buffer cap, falling back to
// DefaultBodyBufferLimit when the string is empty.
func BodyBufferLimitFromString(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return DefaultBodyBufferLimit, nil
	}
	return ParseSize(s)
}

// BodyStorageLimitFromString parses the body storage cap, falling back to
// DefaultBodyStorageLimit when the string is empty.
func BodyStorageLimitFromString(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return DefaultBodyStorageLimit, nil
	}
	return ParseSize(s)
}

// BodyBufferLimit returns the configured body buffer limit in bytes, or
// DefaultBodyBufferLimit when unset/unparseable. Bad input is surfaced
// as a load-time error by validateOperational; this runtime accessor
// falls back to the default so a degraded config still serves.
func (g *Gateway) BodyBufferLimit() int {
	bl := g.settings().Limits
	if bl == nil {
		return int(DefaultBodyBufferLimit)
	}
	n, err := BodyBufferLimitFromString(bl.BodyBuffer)
	if err != nil {
		return int(DefaultBodyBufferLimit)
	}
	return int(n)
}

// BodyStorageLimit returns the configured body storage limit in bytes,
// or DefaultBodyStorageLimit when unset/unparseable.
func (g *Gateway) BodyStorageLimit() int {
	bl := g.settings().Limits
	if bl == nil {
		return int(DefaultBodyStorageLimit)
	}
	n, err := BodyStorageLimitFromString(bl.BodyStorage)
	if err != nil {
		return int(DefaultBodyStorageLimit)
	}
	return int(n)
}

// validateLimits surfaces parse errors at config load time and emits
// a soft warning when the body buffer cap is smaller than the body
// storage cap. The inverse is NOT rejected: a deployment may
// deliberately log more than it rule-matches.
func validateLimits(bl *LimitsBlock) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if bl == nil {
		return diags
	}
	buffer, bErr := BodyBufferLimitFromString(bl.BodyBuffer)
	if bErr != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid limits.body_buffer",
			Detail:   fmt.Sprintf("body_buffer = %q: %v. Use a size string like \"256KiB\" or \"1MiB\".", bl.BodyBuffer, bErr),
		})
	}
	storage, sErr := BodyStorageLimitFromString(bl.BodyStorage)
	if sErr != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid limits.body_storage",
			Detail:   fmt.Sprintf("body_storage = %q: %v. Use a size string like \"64KiB\" or \"256KiB\".", bl.BodyStorage, sErr),
		})
	}
	if bErr == nil && sErr == nil && buffer < storage {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagWarning,
			Summary:  "limits.body_buffer smaller than limits.body_storage",
			Detail: fmt.Sprintf(
				"body_buffer = %d bytes < body_storage = %d bytes. The rules engine will see less body than is persisted to storage. This is allowed, but usually the buffer cap is the larger of the two.",
				buffer, storage,
			),
		})
	}
	return diags
}
