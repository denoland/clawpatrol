package config_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

func TestParseSize(t *testing.T) {
	ok := []struct {
		in   string
		want int64
	}{
		{"1024", 1024},        // bare number = bytes
		{"512B", 512},         // explicit byte unit
		{"512b", 512},         // lowercase unit
		{"256KiB", 256 << 10}, // canonical KiB
		{"256kib", 256 << 10}, // mixed/lower case
		{"  4MiB ", 4 << 20},  // surrounding whitespace
		{"1MB", 1 << 20},      // MB treated as binary alias
		{"2GiB", 2 << 30},     // GiB
		{"64 KiB", 64 << 10},  // space between number and unit
	}
	for _, tc := range ok {
		got, err := config.ParseSize(tc.in)
		if err != nil {
			t.Errorf("ParseSize(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"",       // empty
		"   ",    // whitespace only
		"0",      // zero rejected
		"0KiB",   // zero with unit
		"-1",     // negative
		"-5MiB",  // negative with unit
		"KiB",    // missing magnitude
		"12PiB",  // unknown unit
		"abc",    // non-numeric
		"1.5MiB", // fractional unsupported
	}
	for _, in := range bad {
		if got, err := config.ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) = %d, want error", in, got)
		}
	}
}

func TestBodyCapDefaults(t *testing.T) {
	// A config with no body_caps block must fall back to the historical
	// hardcoded values so existing deployments are unaffected.
	src := `
gateway {
  state_dir = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.test"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`
	gw, diags := config.LoadBytes([]byte(src), "defaults.hcl")
	if diags.HasErrors() {
		t.Fatalf("unexpected load errors: %v", diags)
	}
	if got := gw.RulesEngineBodyCap(); got != config.DefaultRulesEngineBodyCap {
		t.Errorf("RulesEngineBodyCap() = %d, want default %d", got, config.DefaultRulesEngineBodyCap)
	}
	if got := gw.ActionsTableBodyCap(); got != config.DefaultActionsTableBodyCap {
		t.Errorf("ActionsTableBodyCap() = %d, want default %d", got, config.DefaultActionsTableBodyCap)
	}
}

func TestBodyCapConfigured(t *testing.T) {
	src := `
gateway {
  state_dir = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.test"
  body_caps {
    rules_engine  = "2MiB"
    actions_table = "16KiB"
  }
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`
	gw, diags := config.LoadBytes([]byte(src), "configured.hcl")
	if diags.HasErrors() {
		t.Fatalf("unexpected load errors: %v", diags)
	}
	if got, want := gw.RulesEngineBodyCap(), int64(2<<20); got != want {
		t.Errorf("RulesEngineBodyCap() = %d, want %d", got, want)
	}
	if got, want := gw.ActionsTableBodyCap(), int64(16<<10); got != want {
		t.Errorf("ActionsTableBodyCap() = %d, want %d", got, want)
	}
}

func TestBodyCapPartialOverrideKeepsDefault(t *testing.T) {
	// Only one field set — the other must keep its default.
	src := `
gateway {
  state_dir = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.test"
  body_caps {
    actions_table = "128KiB"
  }
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`
	gw, diags := config.LoadBytes([]byte(src), "partial.hcl")
	if diags.HasErrors() {
		t.Fatalf("unexpected load errors: %v", diags)
	}
	if got := gw.RulesEngineBodyCap(); got != config.DefaultRulesEngineBodyCap {
		t.Errorf("RulesEngineBodyCap() = %d, want default %d", got, config.DefaultRulesEngineBodyCap)
	}
	if got, want := gw.ActionsTableBodyCap(), int64(128<<10); got != want {
		t.Errorf("ActionsTableBodyCap() = %d, want %d", got, want)
	}
}

func TestBodyCapInvalidIsLoadError(t *testing.T) {
	src := `
gateway {
  state_dir = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.test"
  body_caps {
    rules_engine = "not-a-size"
  }
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`
	_, diags := config.LoadBytes([]byte(src), "invalid.hcl")
	if !diags.HasErrors() {
		t.Fatalf("expected load error for malformed rules_engine, got none")
	}
	if !strings.Contains(diags.Error(), "body_caps.rules_engine") {
		t.Errorf("error did not mention body_caps.rules_engine: %v", diags)
	}
}

func TestBodyCapInverseEmitsWarningNotError(t *testing.T) {
	// rules_engine < actions_table is allowed (a deployment may log more
	// than it rule-matches) but must surface a warning.
	src := `
gateway {
  state_dir = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.test"
  body_caps {
    rules_engine  = "4KiB"
    actions_table = "1MiB"
  }
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`
	_, diags := config.LoadBytes([]byte(src), "inverse.hcl")
	if diags.HasErrors() {
		t.Fatalf("inverse caps must not be a load error: %v", diags)
	}
	var warned bool
	for _, d := range diags {
		if strings.Contains(d.Summary, "smaller than actions_table") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a warning about rules_engine < actions_table, got: %v", diags)
	}
}
