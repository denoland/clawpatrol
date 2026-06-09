package dnsvip

import (
	"testing"

	"github.com/miekg/dns"
)

func httpsRR(alpn ...string) *dns.HTTPS {
	rr := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 30},
		Priority: 1,
		Target:   ".",
	}}
	if alpn != nil {
		rr.Value = []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: alpn}}
	}
	return rr
}

func alpnOf(rr dns.RR) []string {
	h, ok := rr.(*dns.HTTPS)
	if !ok {
		return nil
	}
	for _, kv := range h.Value {
		if a, ok := kv.(*dns.SVCBAlpn); ok {
			return a.Alpn
		}
	}
	return nil
}

func TestStripH3ALPN(t *testing.T) {
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{1, 2, 3, 4}}

	msg := &dns.Msg{Answer: []dns.RR{
		a,                      // untouched
		httpsRR("h2", "h3"),    // h3 stripped, h2 kept
		httpsRR("h3"),          // h3-only → dropped
		httpsRR("h3-29", "h2"), // draft h3 stripped
		httpsRR(),              // no alpn → kept untouched
	}}

	stripH3ALPN(msg)

	// a, https(h2), https(h3-29→h2), https(no-alpn) remain; the h3-only one is gone.
	if len(msg.Answer) != 4 {
		t.Fatalf("answer count = %d, want 4 (h3-only record should be dropped)", len(msg.Answer))
	}
	for _, rr := range msg.Answer {
		for _, p := range alpnOf(rr) {
			if p == "h3" || p == "h3-29" {
				t.Errorf("h3 ALPN survived: %v", alpnOf(rr))
			}
		}
	}
	// The first surviving HTTPS record kept its non-h3 ALPN.
	if got := alpnOf(msg.Answer[1]); len(got) != 1 || got[0] != "h2" {
		t.Errorf("first HTTPS alpn = %v, want [h2]", got)
	}

	// nil and no-SVCB messages are safe no-ops.
	stripH3ALPN(nil)
	plain := &dns.Msg{Answer: []dns.RR{a}}
	stripH3ALPN(plain)
	if len(plain.Answer) != 1 {
		t.Errorf("plain message altered: %d answers", len(plain.Answer))
	}
}
