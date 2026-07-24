//go:build linux

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestRewriteHostsLines(t *testing.T) {
	const canonical = "hosts:      files dns"
	cases := []struct {
		name        string
		in          string
		wantChanged bool
		wantHosts   []string // ALL hosts-definition lines when changed
	}{
		{
			name:        "fedora resolve short-circuit",
			in:          "passwd: files\nhosts:      files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns\ngroup: files\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			name:        "already files dns - no change",
			in:          "hosts: files dns\n",
			wantChanged: false,
		},
		{
			// myhostname is off the allowlist: self-lookups are served by
			// the synthetic /etc/hosts through `files` instead.
			name:        "drops myhostname",
			in:          "hosts:      files myhostname dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
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
			wantHosts:   []string{canonical},
		},
		{
			name:        "canonicalized when no keepable sources",
			in:          "hosts: resolve [!UNAVAIL=return]\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			// sssd answers via the host's sssd daemon (e.g. an LDAP
			// resolver) without consulting the bind-mounted resolv.conf —
			// off the allowlist, must be dropped (#765).
			name:        "drops sssd module",
			in:          "hosts: files sss dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			name:        "drops ldap and myhostname modules",
			in:          "hosts: files myhostname ldap dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			// dns-first is unusual but intentional; must not be reordered.
			name:        "dns before files not reordered - no change",
			in:          "hosts: dns files\n",
			wantChanged: false,
		},
		{
			name:        "removes resolve and sss together",
			in:          "hosts: files sss resolve [!UNAVAIL=return] dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			name:        "removes mdns and myhostname keeps dns",
			in:          "hosts: files mdns4_minimal [NOTFOUND=return] myhostname dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			// No dns present: canonicalized so the gateway resolv.conf is
			// still consulted.
			name:        "adds dns when absent",
			in:          "hosts: files\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			// Multi-status action bracket contains a space; it must be
			// treated as one token, not shattered by the tokenizer.
			name:        "multi-status bracket on removed module",
			in:          "hosts: files resolve [NOTFOUND=return UNAVAIL=return] dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			// A host-provided action modifier on an allowlisted source can
			// suppress gateway DNS — [NOTFOUND=return] after files makes
			// every name absent from the synthetic /etc/hosts short-circuit
			// before `dns` runs. Modifiers never survive, even "safe"
			// looking ones.
			name:        "action modifier on kept source dropped",
			in:          "hosts: files [NOTFOUND=return] dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			name:        "spaced bracket on kept source dropped",
			in:          "hosts: files [SUCCESS=return  NOTFOUND=continue] dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			name:        "brackets after surviving and removed sources all dropped",
			in:          "hosts: files [SUCCESS=return] resolve [!UNAVAIL=return] dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			// glibc assigns every parsed hosts line to the same slot, so
			// the LAST definition wins — a safe first line must not stop
			// the rewrite from sanitizing a later unsafe one.
			name:        "duplicate definitions - later unsafe line sanitized",
			in:          "hosts: files dns\nhosts: sss dns\n",
			wantChanged: true,
			wantHosts:   []string{"hosts: files dns", canonical},
		},
		{
			// glibc's grammar: whitespace is allowed around the colon.
			name:        "space before colon recognized",
			in:          "hosts : sss dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			// glibc's grammar: the colon is optional.
			name:        "colon-less definition recognized",
			in:          "hosts sss dns\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
		{
			name:        "colon-less definition already safe - no change",
			in:          "hosts files dns\n",
			wantChanged: false,
		},
		{
			// A bare "hosts" with nothing after the name is a glibc syntax
			// error (the line is skipped there), so it is not a definition.
			name:        "bare hosts word is not a definition",
			in:          "hosts\npasswd: files\n",
			wantChanged: false,
		},
		{
			// "hosts:" with empty services defines an empty database in
			// glibc (all lookups NOTFOUND); canonicalize so DNS works.
			name:        "empty services canonicalized",
			in:          "hosts:\n",
			wantChanged: true,
			wantHosts:   []string{canonical},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, changed := rewriteHostsLines(tc.in)
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v (body=%q)", changed, tc.wantChanged, body)
			}
			if !changed {
				return
			}
			// Validate the COMPLETE set of hosts definitions, not just the
			// first — glibc honors the last one, so a missed duplicate is
			// a lockdown bypass.
			hostsLines := func(s string) []string {
				var out []string
				for _, l := range strings.Split(s, "\n") {
					if _, ok := cutHostsDefinition(l); ok {
						out = append(out, l)
					}
				}
				return out
			}
			if got := hostsLines(body); !reflect.DeepEqual(got, tc.wantHosts) {
				t.Fatalf("hosts lines = %q, want %q", got, tc.wantHosts)
			}
			// Non-hosts lines must be preserved verbatim and in order —
			// compare the full sequence, not mere substring membership,
			// so a reordering/duplication regression can't slip through.
			nonHosts := func(s string) []string {
				var out []string
				for _, l := range strings.Split(s, "\n") {
					if _, ok := cutHostsDefinition(l); !ok {
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

func TestChildNetnsSteps(t *testing.T) {
	got := childNetnsSteps("100.64.0.7")
	want := []netnsStep{
		{args: []string{"ip", "link", "set", "lo", "up"}},
		{args: []string{"ip", "link", "set", tunIfName, "mtu", "65535", "up"}},
		{args: []string{"ip", "addr", "add", "100.64.0.7/32", "dev", tunIfName}},
		{args: []string{"ip", "route", "add", "default", "dev", tunIfName}},
		// v6 so fd78:: DNS-VIP answers are routable (#765). The route is
		// scoped to the VIP prefix — NOT default — because the TUN
		// bridge drops IPv6 UDP silently; a default route would stall
		// QUIC/HTTP3 on public AAAA destinations instead of letting them
		// fall back to IPv4. Optional: on a host booted with
		// ipv6.disable=1 these fail, and the v4 VIP path must keep
		// working rather than abort the run.
		{args: []string{"ip", "-6", "addr", "add", runTunAddr6 + "/128", "dev", tunIfName, "nodad"}, optional: true},
		{args: []string{"ip", "-6", "route", "add", "fd78::/64", "dev", tunIfName}, optional: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("childNetnsSteps:\n got %v\nwant %v", got, want)
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
