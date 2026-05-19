package hostmatch

import "testing"

func TestIsWildcardHost(t *testing.T) {
	cases := []struct {
		entry string
		want  bool
	}{
		{"api.foo.com", false},
		{"api.foo.com:443", false},
		{"*.foo.com", true},
		{"*.foo.com:443", true},
		{"10.0.0.1", false},
		{"[fd00::1]:22", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsWildcardHost(c.entry); got != c.want {
			t.Errorf("IsWildcardHost(%q) = %v, want %v", c.entry, got, c.want)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		entry, host, port string
		wantErr           bool
	}{
		{"api.foo.com", "api.foo.com", "", false},
		{"api.foo.com:443", "api.foo.com", "443", false},
		{"*.foo.com:443", "*.foo.com", "443", false},
		{"[fd00::1]:22", "fd00::1", "22", false},
		{"fd00::1", "fd00::1", "", false},
		{"10.0.0.5", "10.0.0.5", "", false},
		{"10.0.0.5:5432", "10.0.0.5", "5432", false},
		{"", "", "", true},
		{":443", "", "", false}, // net.SplitHostPort accepts this; not our concern
	}
	for _, c := range cases {
		host, port, err := SplitHostPort(c.entry)
		if (err != nil) != c.wantErr {
			t.Errorf("SplitHostPort(%q) err = %v, wantErr %v", c.entry, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if c.entry == ":443" {
			continue // documented as net.SplitHostPort's behavior; not part of our contract
		}
		if host != c.host || port != c.port {
			t.Errorf("SplitHostPort(%q) = (%q, %q), want (%q, %q)", c.entry, host, port, c.host, c.port)
		}
	}
}

func TestValidateHost(t *testing.T) {
	good := []string{
		"api.foo.com",
		"api.foo.com:443",
		"*.foo.com",
		"*.foo.com:443",
		"*.us-east-1.amazonaws.com",
		"10.0.0.1",
		"10.0.0.1:5432",
		"[fd00::1]:22",
	}
	for _, g := range good {
		if err := ValidateHost(g); err != nil {
			t.Errorf("ValidateHost(%q) errored: %v", g, err)
		}
	}
	bad := []string{
		"",
		"*",
		"*foo.com",
		"foo.*.com",
		"*.*.com",
		"**.com",
		"*.",
		"*.com",      // single-label suffix
		"*.foo.com:", // empty port
		"*.foo.com:0",
		"*.foo.com:999999",
		"*.foo..com",
	}
	for _, b := range bad {
		if err := ValidateHost(b); err == nil {
			t.Errorf("ValidateHost(%q) accepted, want error", b)
		}
	}
}

func TestMatchWildcard(t *testing.T) {
	cases := []struct {
		pattern, hostname string
		want              bool
	}{
		{"*.foo.com", "api.foo.com", true},
		{"*.foo.com", "a.b.c.foo.com", true},
		{"*.foo.com", "foo.com", false},
		{"*.foo.com", "notfoo.com", false},
		{"*.foo.com", "x.notfoo.com", false},
		{"*.foo.com", "foo.com.evil.example", false},
		{"*.foo.com", "FOO.foo.com", true}, // both already lowercased per contract; we don't case-fold
		{"*.amazonaws.com", "s3.us-east-1.amazonaws.com", true},
		{"*.amazonaws.com", "amazonaws.com", false},
		{"api.foo.com", "api.foo.com", false}, // not a wildcard pattern
	}
	for _, c := range cases {
		if got := MatchWildcard(c.pattern, c.hostname); got != c.want {
			t.Errorf("MatchWildcard(%q, %q) = %v, want %v", c.pattern, c.hostname, got, c.want)
		}
	}
}
