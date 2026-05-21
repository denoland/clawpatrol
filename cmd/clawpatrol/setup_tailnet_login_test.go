package main

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestIsTailnetShapedURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		// MagicDNS hostnames.
		{"https://clawpatrol-gateway.tail9a48e.ts.net", true},
		{"http://clawpatrol-gateway-1.tail9a48e.ts.net:8080/api/onboard", true},
		{"https://CLAWPATROL-GATEWAY.TAIL9A48E.TS.NET", true},
		// CGNAT range, the Tailscale-issued IPs.
		{"http://100.79.206.14:8080", true},
		{"http://100.64.0.1", true},
		{"http://100.127.255.254/api", true},
		// Just outside CGNAT — must NOT match. 100.63.x.x and 100.128.x.x
		// are normal public IPs Tailscale doesn't issue.
		{"http://100.63.255.255", false},
		{"http://100.128.0.0", false},
		// Public hostnames and IPs the bootstrap can't help with.
		{"https://clawpatrol-gateway.example.com", false},
		{"http://1.1.1.1:53", false},
		{"http://192.168.1.5", false},
		// Garbage in -> false, don't crash.
		{"", false},
		{"://nope", false},
		{"not-a-url", false},
	}
	for _, tc := range cases {
		if got := isTailnetShapedURL(tc.url); got != tc.want {
			t.Errorf("isTailnetShapedURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestIsNetworkUnreachableErr(t *testing.T) {
	reachable := []error{
		nil,
		errors.New("http: server gave a 500"),
		errors.New("certificate signed by unknown authority"),
		// TLS handshake timeouts mean the TCP connect succeeded — the
		// gateway is reachable, just misbehaving at L6. A tailnet
		// bootstrap wouldn't help.
		errors.New(`Get "http://x": net/http: TLS handshake timeout`),
	}
	for _, e := range reachable {
		if isNetworkUnreachableErr(e) {
			t.Errorf("isNetworkUnreachableErr(%v) = true, want false", e)
		}
	}
	unreachable := []error{
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.ECONNREFUSED,
		errors.New("dial tcp 1.2.3.4:80: i/o timeout"),
		&net.OpError{Op: "dial", Err: errors.New("no route to host")},
		&net.OpError{Op: "dial", Err: errors.New("network is unreachable")},
		&net.DNSError{Err: "no such host", Name: "no-such-host.invalid", IsNotFound: true},
	}
	for _, e := range unreachable {
		if !isNetworkUnreachableErr(e) {
			t.Errorf("isNetworkUnreachableErr(%v) = false, want true", e)
		}
	}
}

// TestValidateGatewayURL pins the upfront URL check that prevents
// runJoin from writing a bogus value to ~/.clawpatrol/gateway when
// the operator types a scheme-less hostname like "clawpatrol-gw-1".
func TestValidateGatewayURL(t *testing.T) {
	valid := []string{
		"http://clawpatrol-gateway-1:8080",
		"https://clawpatrol-gateway.tail9a48e.ts.net",
		"http://100.79.206.14:8080",
		"https://gw.example.com",
		"http://gw.example.com:80/",
	}
	for _, u := range valid {
		got, err := validateGatewayURL(u)
		if err != nil {
			t.Errorf("validateGatewayURL(%q) returned %v, want nil", u, err)
		}
		if got != u {
			t.Errorf("validateGatewayURL(%q) returned %q, want unchanged", u, got)
		}
	}

	invalid := []struct {
		in      string
		wantSub string
	}{
		{"", "empty"},
		{"   ", "empty"},
		{"clawpatrol-gateway-1", "missing an http:// or https:// scheme"},
		{"clawpatrol-gateway-1:8080", "missing an http:// or https:// scheme"},
		{"ftp://example.com", "missing an http:// or https:// scheme"},
		// scheme-only with no host: rejected on the host check.
		{"http://", "no host"},
	}
	for _, tc := range invalid {
		if _, err := validateGatewayURL(tc.in); err == nil {
			t.Errorf("validateGatewayURL(%q) returned no error, want one containing %q", tc.in, tc.wantSub)
		} else if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("validateGatewayURL(%q) error = %q, want substring %q", tc.in, err.Error(), tc.wantSub)
		}
	}
}
