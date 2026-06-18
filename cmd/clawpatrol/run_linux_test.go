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
		{
			// Regression: a resolv.conf-respecting module like sssd must
			// not be dropped — only resolve/mdns short-circuiters are.
			name:        "preserves sssd module - no change",
			in:          "hosts: files sss dns\n",
			wantChanged: false,
		},
		{
			name:        "preserves ldap module - no change",
			in:          "hosts: files myhostname ldap dns\n",
			wantChanged: false,
		},
		{
			// dns-first is unusual but intentional; must not be reordered.
			name:        "dns before files not reordered - no change",
			in:          "hosts: dns files\n",
			wantChanged: false,
		},
		{
			name:        "removes resolve but keeps sss in place",
			in:          "hosts: files sss resolve [!UNAVAIL=return] dns\n",
			wantChanged: true,
			wantHosts:   "hosts:      files sss dns",
		},
		{
			name:        "removes mdns keeps myhostname and dns",
			in:          "hosts: files mdns4_minimal [NOTFOUND=return] myhostname dns\n",
			wantChanged: true,
			wantHosts:   "hosts:      files myhostname dns",
		},
		{
			// No dns and no bypassing module: dns is appended so the
			// gateway resolv.conf is still consulted.
			name:        "appends dns when absent",
			in:          "hosts: files myhostname\n",
			wantChanged: true,
			wantHosts:   "hosts:      files myhostname dns",
		},
		{
			// Multi-status action bracket contains a space; it must be
			// treated as one token, not shattered by the tokenizer.
			name:        "multi-status bracket on removed module",
			in:          "hosts: files resolve [NOTFOUND=return UNAVAIL=return] dns\n",
			wantChanged: true,
			wantHosts:   "hosts:      files dns",
		},
		{
			// Spaces inside the brackets, no bypassing module → no-op,
			// preserved verbatim (also exercises the kept-bracket path).
			name:        "spaced bracket on kept source - no change",
			in:          "hosts: files [SUCCESS=return  NOTFOUND=continue] dns\n",
			wantChanged: false,
		},
		{
			// A bracket trailing a surviving source must be kept in place
			// while the resolve module ahead of it is removed.
			name:        "keeps bracket after surviving source, drops resolve",
			in:          "hosts: files [SUCCESS=return] resolve [!UNAVAIL=return] dns\n",
			wantChanged: true,
			wantHosts:   "hosts:      files [SUCCESS=return] dns",
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
			// Non-hosts lines must be preserved verbatim and in order —
			// compare the full sequence, not mere substring membership,
			// so a reordering/duplication regression can't slip through.
			nonHosts := func(s string) []string {
				var out []string
				for _, l := range strings.Split(s, "\n") {
					if !strings.HasPrefix(strings.TrimLeft(l, " \t"), "hosts:") {
						out = append(out, l)
					}
				}
				return out
			}
			if before, after := nonHosts(tc.in), nonHosts(body); !reflect.DeepEqual(before, after) {
				t.Fatalf("non-hosts lines changed: %q -> %q", before, after)
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
