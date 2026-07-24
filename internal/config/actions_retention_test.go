package config

import "testing"

func TestValidateRetentionDuration(t *testing.T) {
	// Zero-valued durations ("0s", "0h") are the "0" sentinel spelled
	// differently and must stay valid: they mean disable / keep forever.
	valid := []string{"", "0", "off", "720h", "30m", "1h30m", " 24h ", "0s", "0h"}
	for _, v := range valid {
		if d := validateRetentionDuration("actions_keep", v); len(d) != 0 {
			t.Errorf("validateRetentionDuration(%q) = %v, want no diagnostics", v, d)
		}
	}
	// A bare number, a spaced phrase, or garbage must be rejected at load
	// rather than silently disabling pruning at runtime. Negative
	// durations parse fine but would put the sweep cutoff in the future
	// (delete everything), so they are rejected too.
	invalid := []string{"30", "1 week", "abc", "24hours", "-24h", "-1ns"}
	for _, v := range invalid {
		if d := validateRetentionDuration("actions_keep", v); !d.HasErrors() {
			t.Errorf("validateRetentionDuration(%q) = %v, want an error diagnostic", v, d)
		}
	}
}
