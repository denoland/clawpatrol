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
	r, err := BufferBodyLimitFromString("")
	if err != nil || r != DefaultBufferBodyLimit {
		t.Fatalf("BufferBodyLimitFromString(\"\") = %d, %v; want %d, nil", r, err, DefaultBufferBodyLimit)
	}
	a, err := StorageBodyLimitFromString("   ")
	if err != nil || a != DefaultStorageBodyLimit {
		t.Fatalf("StorageBodyLimitFromString(blank) = %d, %v; want %d, nil", a, err, DefaultStorageBodyLimit)
	}
	r, err = BufferBodyLimitFromString("512KiB")
	if err != nil || r != 512<<10 {
		t.Fatalf("BufferBodyLimitFromString(512KiB) = %d, %v; want %d, nil", r, err, 512<<10)
	}
}

func TestGatewayBodyLimitAccessorsFallBack(t *testing.T) {
	// nil settings/block path must yield the defaults, not panic or 0.
	g := &Gateway{Settings: &GatewaySettings{}}
	if got := g.BufferBodyLimit(); got != int(DefaultBufferBodyLimit) {
		t.Errorf("BufferBodyLimit() = %d, want %d", got, DefaultBufferBodyLimit)
	}
	if got := g.StorageBodyLimit(); got != int(DefaultStorageBodyLimit) {
		t.Errorf("StorageBodyLimit() = %d, want %d", got, DefaultStorageBodyLimit)
	}
	g.Settings.BodyLimits = &BodyLimitsBlock{Buffer: "2MiB", Storage: "16KiB"}
	if got := g.BufferBodyLimit(); got != 2<<20 {
		t.Errorf("BufferBodyLimit() = %d, want %d", got, 2<<20)
	}
	if got := g.StorageBodyLimit(); got != 16<<10 {
		t.Errorf("StorageBodyLimit() = %d, want %d", got, 16<<10)
	}
	// Unparseable values fall back to defaults at runtime.
	g.Settings.BodyLimits = &BodyLimitsBlock{Buffer: "garbage"}
	if got := g.BufferBodyLimit(); got != int(DefaultBufferBodyLimit) {
		t.Errorf("BufferBodyLimit() with bad value = %d, want default %d", got, DefaultBufferBodyLimit)
	}
}

func TestValidateBodyLimits(t *testing.T) {
	// nil block: no diagnostics.
	if d := validateBodyLimits(nil); len(d) != 0 {
		t.Errorf("validateBodyLimits(nil) = %d diags, want 0", len(d))
	}
	// Valid, buffer >= storage: clean.
	if d := validateBodyLimits(&BodyLimitsBlock{Buffer: "1MiB", Storage: "4KiB"}); len(d) != 0 {
		t.Errorf("validateBodyLimits(valid) = %d diags, want 0: %v", len(d), d)
	}
	// buffer < storage: a single warning, not an error.
	d := validateBodyLimits(&BodyLimitsBlock{Buffer: "4KiB", Storage: "1MiB"})
	if d.HasErrors() {
		t.Errorf("validateBodyLimits(buffer<storage) returned errors, want warning only: %v", d)
	}
	if len(d) != 1 {
		t.Fatalf("validateBodyLimits(buffer<storage) = %d diags, want 1 warning", len(d))
	}
	// Bad value: an error diagnostic.
	d = validateBodyLimits(&BodyLimitsBlock{Buffer: "nope"})
	if !d.HasErrors() {
		t.Errorf("validateBodyLimits(bad buffer) = %v, want an error", d)
	}
}
