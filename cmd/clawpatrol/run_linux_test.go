//go:build linux

package main

import (
	"reflect"
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
