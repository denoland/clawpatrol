package config

import "testing"

func TestMatchDashboardOperator(t *testing.T) {
	cases := []struct {
		name  string
		login string
		allow []string
		want  bool
	}{
		{"exact match", "alice@example.com", []string{"alice@example.com"}, true},
		{"exact mismatch", "alice@example.com", []string{"bob@example.com"}, false},
		{"wildcard match", "alice@example.com", []string{"*@example.com"}, true},
		{"wildcard match different user", "bob@example.com", []string{"*@example.com"}, true},
		{"wildcard non-match adjacent prefix", "alice@evil-example.com", []string{"*@example.com"}, false},
		{"wildcard non-match adjacent suffix", "alice@example.com.evil.com", []string{"*@example.com"}, false},
		{"wildcard non-match equal length", "@example.com", []string{"*@example.com"}, false},
		{"empty login never matches", "", []string{"*@example.com", "alice@example.com"}, false},
		{"empty allowlist", "alice@example.com", nil, false},
		{"multiple entries, second matches", "alice@example.com", []string{"bob@example.com", "*@example.com"}, true},
		{"tagged device login does not match user wildcard", "tagged-devices", []string{"*@example.com"}, false},
	}
	for _, tc := range cases {
		got := MatchDashboardOperator(tc.login, tc.allow)
		if got != tc.want {
			t.Errorf("%s: MatchDashboardOperator(%q, %v) = %v, want %v",
				tc.name, tc.login, tc.allow, got, tc.want)
		}
	}
}

func TestValidateDashboardOperatorEntry(t *testing.T) {
	ok := []string{"alice@example.com", "bob@example.org", "*@example.com"}
	for _, e := range ok {
		if err := ValidateDashboardOperatorEntry(e); err != nil {
			t.Errorf("ValidateDashboardOperatorEntry(%q) = %v, want nil", e, err)
		}
	}
	bad := []string{"", "alice", "@example.com", "alice@", "*", "*@", "*example.com", "*@example.*com", "foo*@example.com", "foo@bar@baz"}
	for _, e := range bad {
		if err := ValidateDashboardOperatorEntry(e); err == nil {
			t.Errorf("ValidateDashboardOperatorEntry(%q) = nil, want error", e)
		}
	}
}
