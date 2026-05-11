package main

import "testing"

func TestRequireSecureGatewayURL(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"https://gw.example.com:9080", true},
		{"https://gw.example.com", true},
		{"http://localhost:9080", true},
		{"http://localhost", true},
		{"http://127.0.0.1:9080", true},
		{"http://127.0.0.1", true},
		{"http://[::1]:9080", true},
		{"http://gw.example.com:9080", false},
		{"http://example.com", false},
		{"http://1.2.3.4", false},
		{"ftp://example.com", false},
		{"gw.example.com:9080", false},
		{"", false},
	}
	for _, c := range cases {
		err := requireSecureGatewayURL(c.in)
		if (err == nil) != c.ok {
			t.Errorf("requireSecureGatewayURL(%q) = %v, want ok=%v",
				c.in, err, c.ok)
		}
	}
}
