package config

import "testing"

func TestValidateRetentionDuration(t *testing.T) {
	valid := []string{"", "0", "off", "720h", "30m", "1h30m", " 24h "}
	for _, v := range valid {
		if d := validateRetentionDuration("actions_keep", v); len(d) != 0 {
			t.Errorf("validateRetentionDuration(%q) = %v, want no diagnostics", v, d)
		}
	}
	// A bare number, a spaced phrase, or garbage must be rejected at load
	// rather than silently disabling pruning at runtime.
	invalid := []string{"30", "1 week", "abc", "24hours"}
	for _, v := range invalid {
		if d := validateRetentionDuration("actions_keep", v); !d.HasErrors() {
			t.Errorf("validateRetentionDuration(%q) = %v, want an error diagnostic", v, d)
		}
	}
}
