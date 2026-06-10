package main

import "testing"

// isTailnetOnlyURL gates the join-time decision to print a QR code
// (true) vs spawn a local browser (false). Tailnet-only = 100.64/10
// CGNAT IP or *.ts.net MagicDNS host. Anything else — public DNS, RFC
// 1918, loopback — falls through to the regular tryOpen path.
func TestIsTailnetOnlyURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		{"100.x cgnat ip", "http://100.79.206.14:8080/#/onboard/ABCD-1234", true},
		{"100.64.0.1 lower bound", "http://100.64.0.1/", true},
		{"100.127.255.254 upper bound", "http://100.127.255.254/", true},
		{"100.128.x outside cgnat", "http://100.128.0.1/", false},
		{"100.63.x outside cgnat", "http://100.63.255.255/", false},
		{".ts.net magicdns", "https://clawpatrol-gateway.tail9a48e.ts.net/#/onboard/X", true},
		{".TS.NET case-insensitive", "https://gw.TAIL9A48E.TS.NET/", true},
		{"public dns", "https://gw.example.com/", false},
		{"loopback ip", "http://127.0.0.1:8080/", false},
		{"rfc1918 ip", "http://10.0.0.5/", false},
		{"empty url", "", false},
		{"garbage url", "::not-a-url::", false},
		{"missing host", "http:///path", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTailnetOnlyURL(c.url); got != c.want {
				t.Errorf("isTailnetOnlyURL(%q) = %v; want %v", c.url, got, c.want)
			}
		})
	}
}

// approveBaseFromVerifyURL must return the dashboard origin of the
// verify URL so auto-approve POSTs to the operator-gated API (where
// the bootstrap node's whois identity is checked), not the public
// Funnel join URL whose allowlist 404s /api/onboard/approve.
func TestApproveBaseFromVerifyURL(t *testing.T) {
	const fallback = "https://clawpatrol-gateway.tail9a48e.ts.net"
	cases := []struct {
		name      string
		verifyURL string
		want      string
	}{
		{"tailnet dashboard url", "http://100.79.206.14:8080/#/onboard/NDVL-4343", "http://100.79.206.14:8080"},
		{"public dashboard url", "https://gw.example.com/#/onboard/X", "https://gw.example.com"},
		{"empty falls back", "", fallback},
		{"garbage falls back", "::not-a-url::", fallback},
		{"missing host falls back", "http:///#/onboard/X", fallback},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := approveBaseFromVerifyURL(c.verifyURL, fallback); got != c.want {
				t.Errorf("approveBaseFromVerifyURL(%q) = %q; want %q", c.verifyURL, got, c.want)
			}
		})
	}
}
