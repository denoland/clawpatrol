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

func TestBodyLimitFromStringDefaults(t *testing.T) {
	r, err := BodyBufferLimitFromString("")
	if err != nil || r != DefaultBodyBufferLimit {
		t.Fatalf("BodyBufferLimitFromString(\"\") = %d, %v; want %d, nil", r, err, DefaultBodyBufferLimit)
	}
	a, err := BodyStorageLimitFromString("   ")
	if err != nil || a != DefaultBodyStorageLimit {
		t.Fatalf("BodyStorageLimitFromString(blank) = %d, %v; want %d, nil", a, err, DefaultBodyStorageLimit)
	}
	r, err = BodyBufferLimitFromString("512KiB")
	if err != nil || r != 512<<10 {
		t.Fatalf("BodyBufferLimitFromString(512KiB) = %d, %v; want %d, nil", r, err, 512<<10)
	}
}

func TestGatewayBodyLimitAccessorsFallBack(t *testing.T) {
	// nil settings/block path must yield the defaults, not panic or 0.
	g := &Gateway{Settings: &GatewaySettings{}}
	if got := g.BodyBufferLimit(); got != int(DefaultBodyBufferLimit) {
		t.Errorf("BodyBufferLimit() = %d, want %d", got, DefaultBodyBufferLimit)
	}
	if got := g.BodyStorageLimit(); got != int(DefaultBodyStorageLimit) {
		t.Errorf("BodyStorageLimit() = %d, want %d", got, DefaultBodyStorageLimit)
	}
	g.Settings.Limits = &LimitsBlock{BodyBuffer: "2MiB", BodyStorage: "16KiB"}
	if got := g.BodyBufferLimit(); got != 2<<20 {
		t.Errorf("BodyBufferLimit() = %d, want %d", got, 2<<20)
	}
	if got := g.BodyStorageLimit(); got != 16<<10 {
		t.Errorf("BodyStorageLimit() = %d, want %d", got, 16<<10)
	}
	// Unparseable values fall back to defaults at runtime.
	g.Settings.Limits = &LimitsBlock{BodyBuffer: "garbage"}
	if got := g.BodyBufferLimit(); got != int(DefaultBodyBufferLimit) {
		t.Errorf("BodyBufferLimit() with bad value = %d, want default %d", got, DefaultBodyBufferLimit)
	}
}

func TestValidateBodyLimits(t *testing.T) {
	// nil block: no diagnostics.
	if d := validateLimits(nil); len(d) != 0 {
		t.Errorf("validateLimits(nil) = %d diags, want 0", len(d))
	}
	// Valid, buffer >= storage: clean.
	if d := validateLimits(&LimitsBlock{BodyBuffer: "1MiB", BodyStorage: "4KiB"}); len(d) != 0 {
		t.Errorf("validateLimits(valid) = %d diags, want 0: %v", len(d), d)
	}
	// buffer < storage: a single warning, not an error.
	d := validateLimits(&LimitsBlock{BodyBuffer: "4KiB", BodyStorage: "1MiB"})
	if d.HasErrors() {
		t.Errorf("validateLimits(buffer<storage) returned errors, want warning only: %v", d)
	}
	if len(d) != 1 {
		t.Fatalf("validateLimits(buffer<storage) = %d diags, want 1 warning", len(d))
	}
	// Bad value: an error diagnostic.
	d = validateLimits(&LimitsBlock{BodyBuffer: "nope"})
	if !d.HasErrors() {
		t.Errorf("validateLimits(bad buffer) = %v, want an error", d)
	}
}
