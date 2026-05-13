//go:build linux

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitWGAddresses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			// Regression: gateway-emitted wg-quick conf carries both
			// v4 and v6 in a single `Address =` line. Passing the
			// whole comma-joined string to `ip addr add` fails with
			// "any valid prefix is expected rather than ...".
			name: "dual stack",
			in:   "10.55.0.5/32, fd77::5/128",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "dual stack no space after comma",
			in:   "10.55.0.5/32,fd77::5/128",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "v4 only",
			in:   "10.55.0.5/32",
			want: []string{"10.55.0.5/32"},
		},
		{
			name: "v6 only",
			in:   "fd77::5/128",
			want: []string{"fd77::5/128"},
		},
		{
			name: "missing prefix v4 defaults to /32",
			in:   "10.55.0.5",
			want: []string{"10.55.0.5/32"},
		},
		{
			name: "missing prefix v6 defaults to /128",
			in:   "fd77::5",
			want: []string{"fd77::5/128"},
		},
		{
			name: "extra whitespace and empty parts",
			in:   "  10.55.0.5/32 ,, fd77::5/128 ,",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "empty input",
			in:   "",
			want: nil,
		},
		{
			name: "only whitespace and commas",
			in:   " , , ",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitWGAddresses(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitWGAddresses(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestUserNSCloneHint(t *testing.T) {
	const (
		apparmor = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
		clone    = "/proc/sys/kernel/unprivileged_userns_clone"
	)
	cases := []struct {
		name   string
		sysctl map[string]string
		want   string // substring the hint must contain
	}{
		{
			name:   "ubuntu 24.04: apparmor restriction on, no legacy sysctl",
			sysctl: map[string]string{apparmor: "1"},
			want:   "apparmor_restrict_unprivileged_userns=0",
		},
		{
			name:   "older ubuntu / debian: legacy sysctl=0, no apparmor sysctl",
			sysctl: map[string]string{clone: "0"},
			want:   "unprivileged_userns_clone=1",
		},
		{
			name:   "ubuntu 24.04 with apparmor already off — fallback to neither",
			sysctl: map[string]string{apparmor: "0"},
			want:   "Ubuntu 24.04",
		},
		{
			name:   "neither sysctl present — fallback covers both",
			sysctl: map[string]string{},
			want:   "Older Ubuntu/Debian",
		},
		{
			name:   "apparmor wins when both are restrictive",
			sysctl: map[string]string{apparmor: "1", clone: "0"},
			want:   "apparmor_restrict_unprivileged_userns=0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probe := func(p string) (string, bool) {
				v, ok := c.sysctl[p]
				return v, ok
			}
			got := userNSCloneHintFrom(probe)
			if !strings.Contains(got, c.want) {
				t.Errorf("hint missing %q\nfull hint:\n%s", c.want, got)
			}
		})
	}
}
