package extplugin

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestValidateBrokeredDialTarget(t *testing.T) {
	ch := &runtime.ConnHandle{
		UpstreamHost: "api.example.com",
		DstPort:      8443,
	}
	hosts := []string{"demo.invalid", "alt.invalid:9000"}
	dial := []string{"upstream.test:8000", "*.svc.test:443"}

	allow := []string{
		"api.example.com:8443", // agent's original target
		"API.EXAMPLE.COM:8443", // case-insensitive
		"demo.invalid:8443",    // bare hosts entry, agent dst port
		"demo.invalid:443",     // bare hosts entry, https default
		"demo.invalid:80",      // bare hosts entry, http default
		"alt.invalid:9000",     // exact hosts entry
		"upstream.test:8000",   // dial allow-list exact
		"a.svc.test:443",       // dial wildcard
		"b.c.svc.test:443",     // dial wildcard, deeper label
	}
	deny := []string{
		"api.example.com:443",  // original host, wrong port
		"evil.example.com:443", // unrelated host
		"alt.invalid:9001",     // hosts entry, wrong port
		"upstream.test:8001",   // dial entry, wrong port
		"svc.test:443",         // wildcard must not match the bare suffix
		"xsvc.test:443",        // wildcard needs a label boundary
		"demo.invalid:25",      // bare hosts entry, non-default port
	}
	for _, addr := range allow {
		if err := validateBrokeredDialTarget(ch, hosts, dial, addr); err != nil {
			t.Errorf("addr %q: unexpectedly refused: %v", addr, err)
		}
	}
	for _, addr := range deny {
		if err := validateBrokeredDialTarget(ch, hosts, dial, addr); err == nil {
			t.Errorf("addr %q: unexpectedly allowed", addr)
		}
	}

	// Malformed addresses.
	for _, addr := range []string{"", "no-port", "host:bad", "host:0", ":443"} {
		if err := validateBrokeredDialTarget(ch, hosts, dial, addr); err == nil {
			t.Errorf("malformed addr %q: unexpectedly allowed", addr)
		}
	}

	// No UpstreamHost (direct-IP dispatch): rule 1 must not fire.
	chNoHost := &runtime.ConnHandle{DstPort: 8443}
	if err := validateBrokeredDialTarget(chNoHost, nil, nil, ":8443"); err == nil {
		t.Error("empty host matched empty UpstreamHost")
	}
}

func TestCheckDialTarget(t *testing.T) {
	good := []string{"host.tld:443", "*.svc.tld:8080", "10.0.0.1:9000", "[::1]:80"}
	for _, e := range good {
		if err := checkDialTarget(e); err != nil {
			t.Errorf("entry %q rejected: %v", e, err)
		}
	}
	bad := []string{"host.tld", "host:tld:99", "*.x.y", "*x.y:443", "a.*.y:443", "host:0", "host:99999", ":443"}
	for _, e := range bad {
		if err := checkDialTarget(e); err == nil {
			t.Errorf("entry %q accepted", e)
		}
	}
}
