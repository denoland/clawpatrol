//go:build linux

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestRewriteHostsLine(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantChanged bool
		wantHosts   string // expected hosts: line when changed
	}{
		{
			name:        "fedora resolve short-circuit",
			in:          "passwd: files\nhosts:      files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns\ngroup: files\n",
			wantChanged: true,
			wantHosts:   "hosts:      files myhostname dns",
		},
		{
			name:        "already files dns - no change",
			in:          "hosts: files dns\n",
			wantChanged: false,
		},
		{
			name:        "already sanitized form - no change",
			in:          "hosts:      files myhostname dns\n",
			wantChanged: false,
		},
		{
			name:        "no hosts line",
			in:          "passwd: files\ngroup: files\n",
			wantChanged: false,
		},
		{
			name:        "empty",
			in:          "",
			wantChanged: false,
		},
		{
			name:        "trailing comment stripped",
			in:          "hosts: files resolve [!UNAVAIL=return] dns # managed\n",
			wantChanged: true,
			wantHosts:   "hosts:      files dns",
		},
		{
			name:        "only dns appended when no keepable sources",
			in:          "hosts: resolve [!UNAVAIL=return]\n",
			wantChanged: true,
			wantHosts:   "hosts:      dns",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, changed := rewriteHostsLine(tc.in)
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v (body=%q)", changed, tc.wantChanged, body)
			}
			if !changed {
				return
			}
			var got string
			for _, l := range strings.Split(body, "\n") {
				if strings.HasPrefix(strings.TrimLeft(l, " \t"), "hosts:") {
					got = l
					break
				}
			}
			if got != tc.wantHosts {
				t.Fatalf("hosts line = %q, want %q", got, tc.wantHosts)
			}
			// Non-hosts lines must be preserved verbatim.
			for _, l := range strings.Split(tc.in, "\n") {
				if l == "" || strings.HasPrefix(strings.TrimLeft(l, " \t"), "hosts:") {
					continue
				}
				if !strings.Contains(body, l) {
					t.Fatalf("line %q dropped from rewritten body", l)
				}
			}
		})
	}
}

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
