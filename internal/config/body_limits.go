package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

const (
	// DefaultBufferBodyLimit is the fallback for
	// gateway.body_limits.buffer: the most request/response body the
	// gateway buffers before handing it to the rules engine. 1 MiB
	// preserves the historical hardcoded maxHTTPMatchBody value.
	DefaultBufferBodyLimit int64 = 1 << 20

	// DefaultStorageBodyLimit is the fallback for
	// gateway.body_limits.storage: the most body the gateway keeps
	// when persisting an action's request/response sample to the audit
	// log. 4 KiB preserves the historical hardcoded sampler cap.
	DefaultStorageBodyLimit int64 = 4096
)

// BodyLimitsBlock is the optional `body_limits { ... }` sub-block inside
// `gateway { ... }`. It exposes the two independent body-size limits as
// human-readable size strings (e.g. "256KiB", "1MiB"):
//
//   - Buffer bounds the hot-path buffer the rules engine matches
//     against. Trade-off: latency / memory vs. how much body rules see.
//   - Storage bounds the cold-storage sample persisted per action.
//     Trade-off: disk / db size vs. how useful the action details page
//     is for debugging.
//
// Both are independent: a deployment may log more (or less) than it
// rule-matches. Empty fields fall back to the Default*BodyLimit
// constants, which equal today's hardcoded behavior.
type BodyLimitsBlock struct {
	Buffer  string `hcl:"buffer,optional"`
	Storage string `hcl:"storage,optional"`
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

// BufferBodyLimitFromString parses the buffer cap, falling back to
// DefaultBufferBodyLimit when the string is empty.
func BufferBodyLimitFromString(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return DefaultBufferBodyLimit, nil
	}
	return ParseSize(s)
}

// StorageBodyLimitFromString parses the storage cap, falling back to
// DefaultStorageBodyLimit when the string is empty.
func StorageBodyLimitFromString(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return DefaultStorageBodyLimit, nil
	}
	return ParseSize(s)
}

// BufferBodyLimit returns the configured buffer body limit in bytes, or
// DefaultBufferBodyLimit when unset/unparseable. Bad input is surfaced
// as a load-time error by validateOperational; this runtime accessor
// falls back to the default so a degraded config still serves.
func (g *Gateway) BufferBodyLimit() int {
	bl := g.settings().BodyLimits
	if bl == nil {
		return int(DefaultBufferBodyLimit)
	}
	n, err := BufferBodyLimitFromString(bl.Buffer)
	if err != nil {
		return int(DefaultBufferBodyLimit)
	}
	return int(n)
}

// StorageBodyLimit returns the configured storage body limit in bytes,
// or DefaultStorageBodyLimit when unset/unparseable.
func (g *Gateway) StorageBodyLimit() int {
	bl := g.settings().BodyLimits
	if bl == nil {
		return int(DefaultStorageBodyLimit)
	}
	n, err := StorageBodyLimitFromString(bl.Storage)
	if err != nil {
		return int(DefaultStorageBodyLimit)
	}
	return int(n)
}

// validateBodyLimits surfaces parse errors at config load time and emits
// a soft warning when the buffer cap is smaller than the storage cap.
// The inverse is NOT rejected: a deployment may deliberately log more
// than it rule-matches.
func validateBodyLimits(bl *BodyLimitsBlock) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if bl == nil {
		return diags
	}
	buffer, bErr := BufferBodyLimitFromString(bl.Buffer)
	if bErr != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid body_limits.buffer",
			Detail:   fmt.Sprintf("buffer = %q: %v. Use a size string like \"256KiB\" or \"1MiB\".", bl.Buffer, bErr),
		})
	}
	storage, sErr := StorageBodyLimitFromString(bl.Storage)
	if sErr != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid body_limits.storage",
			Detail:   fmt.Sprintf("storage = %q: %v. Use a size string like \"64KiB\" or \"256KiB\".", bl.Storage, sErr),
		})
	}
	if bErr == nil && sErr == nil && buffer < storage {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagWarning,
			Summary:  "body_limits.buffer smaller than body_limits.storage",
			Detail: fmt.Sprintf(
				"buffer = %d bytes < storage = %d bytes. The rules engine will see less body than is persisted to storage. This is allowed, but usually the buffer cap is the larger of the two.",
				buffer, storage,
			),
		})
	}
	return diags
}
