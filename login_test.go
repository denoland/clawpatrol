package main

import (
	"io"
	"os"
	"testing"
)

func TestCheckGatewayURL(t *testing.T) {
	cases := []struct {
		in       string
		ok       bool
		wantWarn bool
	}{
		{"https://gw.example.com:9080", true, false},
		{"https://gw.example.com", true, false},
		{"http://localhost:9080", true, false},
		{"http://localhost", true, false},
		{"http://127.0.0.1:9080", true, false},
		{"http://127.0.0.1", true, false},
		{"http://[::1]:9080", true, false},
		{"http://gw.example.com:9080", true, true},
		{"http://example.com", true, true},
		{"http://1.2.3.4", true, true},
		{"ftp://example.com", false, false},
		{"gw.example.com:9080", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		err := checkGatewayURL(c.in)
		_ = w.Close()
		os.Stderr = old
		buf, _ := io.ReadAll(r)
		warned := len(buf) > 0
		if (err == nil) != c.ok {
			t.Errorf("checkGatewayURL(%q) err=%v, want ok=%v",
				c.in, err, c.ok)
		}
		if warned != c.wantWarn {
			t.Errorf("checkGatewayURL(%q) warned=%v, want warn=%v",
				c.in, warned, c.wantWarn)
		}
	}
}
