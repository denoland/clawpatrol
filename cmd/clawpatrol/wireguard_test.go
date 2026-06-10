package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestWGClientEndpoint(t *testing.T) {
	cases := []struct {
		name       string
		wgEnd      string
		publicURL  string
		listenPort int
		want       string
		wantErr    bool
	}{
		{
			name:      "empty wg_endpoint uses public_url host + default port",
			wgEnd:     "",
			publicURL: "https://gw.example.com:9080",
			want:      "gw.example.com:51820",
		},
		{
			name:       "listen_port becomes advertised port when endpoint omits one",
			wgEnd:      "",
			publicURL:  "https://gw.example.com",
			listenPort: 41820,
			want:       "gw.example.com:41820",
		},
		{
			name:       "endpoint port overrides listen_port (split-host NAT)",
			wgEnd:      "1.2.3.4:51820",
			publicURL:  "https://gw.example.com",
			listenPort: 41820,
			want:       "1.2.3.4:51820",
		},
		{
			name:      "wildcard host + port uses public_url",
			wgEnd:     "0.0.0.0:51820",
			publicURL: "https://gw.example.com",
			want:      "gw.example.com:51820",
		},
		{
			name:      "wildcard host + custom port",
			wgEnd:     "0.0.0.0:41820",
			publicURL: "https://gw.example.com",
			want:      "gw.example.com:41820",
		},
		{
			name:      "port-only form",
			wgEnd:     ":41820",
			publicURL: "https://gw.example.com",
			want:      "gw.example.com:41820",
		},
		{
			name:      "v6 wildcard uses public_url",
			wgEnd:     "[::]:51820",
			publicURL: "https://gw.example.com",
			want:      "gw.example.com:51820",
		},
		{
			name:      "non-wildcard host wins (escape hatch)",
			wgEnd:     "1.2.3.4:51820",
			publicURL: "https://dash.example.com",
			want:      "1.2.3.4:51820",
		},
		{
			name:      "hostname in wg_endpoint wins",
			wgEnd:     "wg.example.com:51820",
			publicURL: "https://dash.example.com",
			want:      "wg.example.com:51820",
		},
		{
			name:      "no public_url and wildcard wg_endpoint errors",
			wgEnd:     "0.0.0.0:51820",
			publicURL: "",
			wantErr:   true,
		},
		{
			name:      "neither set errors",
			wgEnd:     "",
			publicURL: "",
			wantErr:   true,
		},
		{
			name:      "malformed wg_endpoint errors",
			wgEnd:     "no-port-here",
			publicURL: "https://gw.example.com",
			wantErr:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wgClientEndpoint(tc.wgEnd, tc.publicURL, tc.listenPort)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWGBindPort(t *testing.T) {
	if got := wgBindPort(0); got != defaultWGListenPort {
		t.Errorf("wgBindPort(0) = %d, want %d (default)", got, defaultWGListenPort)
	}
	if got := wgBindPort(41820); got != 41820 {
		t.Errorf("wgBindPort(41820) = %d, want 41820", got)
	}
}

// TestStartWGServerHonorsListenPort is the regression guard for
// cl-94cf: wireguard.listen_port used to be parsed all the way into
// JoinConfig and then silently dropped (StartWGServer derived the bind
// port from the endpoint instead). Boot the device with an explicit
// listen_port and confirm wireguard-go actually bound it.
func TestStartWGServerHonorsListenPort(t *testing.T) {
	port := freeUDPPort(t)

	db, err := OpenDB(filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	prevDB := globalDB
	globalDB = db
	t.Cleanup(func() { globalDB = prevDB })

	wg, err := StartWGServer(JoinConfig{
		WGSubnetCIDR: "10.55.0.0/24",
		WGListenPort: port,
	})
	if err != nil {
		t.Fatalf("StartWGServer: %v", err)
	}
	t.Cleanup(func() { wg.dev.Close() })

	cfg, err := wg.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	want := fmt.Sprintf("listen_port=%d", port)
	if !strings.Contains(cfg, want) {
		t.Fatalf("device did not bind configured port: got config %q, want substring %q", cfg, want)
	}
}

// freeUDPPort returns a UDP port that was free at call time. Small
// race window between close and reuse, but fine for a single test.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}
