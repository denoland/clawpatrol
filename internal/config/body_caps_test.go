package config

import "testing"

func TestParseSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1024", 1024, false},        // bare bytes
		{"1024B", 1024, false},       // explicit bytes
		{"256KiB", 256 << 10, false}, // KiB
		{"1MiB", 1 << 20, false},     // MiB
		{"2GiB", 2 << 30, false},     // GiB
		{"256kib", 256 << 10, false}, // mixed/lower case
		{"1MIB", 1 << 20, false},     // upper case
		{"  64KiB  ", 64 << 10, false},
		{"4K", 4 << 10, false}, // short unit
		{"0", 0, true},         // zero rejected
		{"0KiB", 0, true},      // zero rejected (with unit)
		{"-5", 0, true},        // negative rejected
		{"-1MiB", 0, true},     // negative rejected (with unit)
		{"", 0, true},          // empty rejected
		{"KiB", 0, true},       // missing numeric value
		{"12pib", 0, true},     // unknown unit
		{"abc", 0, true},       // non-numeric
		{"1.5MiB", 0, true},    // fractional not supported
	}
	for _, tc := range cases {
		got, err := ParseSize(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSize(%q) = %d, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSize(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestBodyCapFromStringDefaults(t *testing.T) {
	r, err := RulesEngineBodyCapFromString("")
	if err != nil || r != DefaultRulesEngineBodyCap {
		t.Fatalf("RulesEngineBodyCapFromString(\"\") = %d, %v; want %d, nil", r, err, DefaultRulesEngineBodyCap)
	}
	a, err := ActionsTableBodyCapFromString("   ")
	if err != nil || a != DefaultActionsTableBodyCap {
		t.Fatalf("ActionsTableBodyCapFromString(blank) = %d, %v; want %d, nil", a, err, DefaultActionsTableBodyCap)
	}
	r, err = RulesEngineBodyCapFromString("512KiB")
	if err != nil || r != 512<<10 {
		t.Fatalf("RulesEngineBodyCapFromString(512KiB) = %d, %v; want %d, nil", r, err, 512<<10)
	}
}

func TestGatewayBodyCapAccessorsFallBack(t *testing.T) {
	// nil settings/block path must yield the defaults, not panic or 0.
	g := &Gateway{Settings: &GatewaySettings{}}
	if got := g.RulesEngineBodyCap(); got != int(DefaultRulesEngineBodyCap) {
		t.Errorf("RulesEngineBodyCap() = %d, want %d", got, DefaultRulesEngineBodyCap)
	}
	if got := g.ActionsTableBodyCap(); got != int(DefaultActionsTableBodyCap) {
		t.Errorf("ActionsTableBodyCap() = %d, want %d", got, DefaultActionsTableBodyCap)
	}
	g.Settings.BodyCaps = &BodyCapsBlock{RulesEngine: "2MiB", ActionsTable: "16KiB"}
	if got := g.RulesEngineBodyCap(); got != 2<<20 {
		t.Errorf("RulesEngineBodyCap() = %d, want %d", got, 2<<20)
	}
	if got := g.ActionsTableBodyCap(); got != 16<<10 {
		t.Errorf("ActionsTableBodyCap() = %d, want %d", got, 16<<10)
	}
	// Unparseable values fall back to defaults at runtime.
	g.Settings.BodyCaps = &BodyCapsBlock{RulesEngine: "garbage"}
	if got := g.RulesEngineBodyCap(); got != int(DefaultRulesEngineBodyCap) {
		t.Errorf("RulesEngineBodyCap() with bad value = %d, want default %d", got, DefaultRulesEngineBodyCap)
	}
}

func TestValidateBodyCaps(t *testing.T) {
	// nil block: no diagnostics.
	if d := validateBodyCaps(nil); len(d) != 0 {
		t.Errorf("validateBodyCaps(nil) = %d diags, want 0", len(d))
	}
	// Valid, rules >= actions: clean.
	if d := validateBodyCaps(&BodyCapsBlock{RulesEngine: "1MiB", ActionsTable: "4KiB"}); len(d) != 0 {
		t.Errorf("validateBodyCaps(valid) = %d diags, want 0: %v", len(d), d)
	}
	// rules < actions: a single warning, not an error.
	d := validateBodyCaps(&BodyCapsBlock{RulesEngine: "4KiB", ActionsTable: "1MiB"})
	if d.HasErrors() {
		t.Errorf("validateBodyCaps(rules<actions) returned errors, want warning only: %v", d)
	}
	if len(d) != 1 {
		t.Fatalf("validateBodyCaps(rules<actions) = %d diags, want 1 warning", len(d))
	}
	// Bad value: an error diagnostic.
	d = validateBodyCaps(&BodyCapsBlock{RulesEngine: "nope"})
	if !d.HasErrors() {
		t.Errorf("validateBodyCaps(bad rules_engine) = %v, want an error", d)
	}
}
