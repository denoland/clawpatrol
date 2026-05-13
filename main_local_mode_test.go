package main

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestCheckLocalModeBinds(t *testing.T) {
	tests := []struct {
		name        string
		cfg         config.Gateway
		wantErr     bool
		wantContain string
	}{
		{
			name:    "non-local mode leaves any bind alone",
			cfg:     config.Gateway{Control: "wireguard", Listen: "0.0.0.0:8443", InfoListen: "0.0.0.0:8080"},
			wantErr: false,
		},
		{
			name:    "empty control behaves like non-local",
			cfg:     config.Gateway{Listen: "0.0.0.0:8443", InfoListen: "0.0.0.0:8080"},
			wantErr: false,
		},
		{
			name:    "local mode loopback v4 ok",
			cfg:     config.Gateway{Control: "local", Listen: "127.0.0.1:8443", InfoListen: "127.0.0.1:8080"},
			wantErr: false,
		},
		{
			name:    "local mode loopback v6 ok",
			cfg:     config.Gateway{Control: "local", Listen: "[::1]:8443", InfoListen: "[::1]:8080"},
			wantErr: false,
		},
		{
			name:    "local mode localhost ok",
			cfg:     config.Gateway{Control: "local", Listen: "localhost:8443", InfoListen: "localhost:8080"},
			wantErr: false,
		},
		{
			name:        "local mode rejects 0.0.0.0 on listen",
			cfg:         config.Gateway{Control: "local", Listen: "0.0.0.0:8443", InfoListen: "127.0.0.1:8080"},
			wantErr:     true,
			wantContain: `listen="0.0.0.0:8443"`,
		},
		{
			name:        "local mode rejects bare :port",
			cfg:         config.Gateway{Control: "local", Listen: ":8443", InfoListen: "127.0.0.1:8080"},
			wantErr:     true,
			wantContain: `listen=":8443"`,
		},
		{
			name:        "local mode rejects LAN IP on info_listen",
			cfg:         config.Gateway{Control: "local", Listen: "127.0.0.1:8443", InfoListen: "192.168.1.10:8080"},
			wantErr:     true,
			wantContain: `info_listen="192.168.1.10:8080"`,
		},
		{
			name:        "local mode rejects [::] (any v6)",
			cfg:         config.Gateway{Control: "local", Listen: "[::]:8443", InfoListen: "127.0.0.1:8080"},
			wantErr:     true,
			wantContain: `listen="[::]:8443"`,
		},
		{
			name:    "local mode case-insensitive",
			cfg:     config.Gateway{Control: "LOCAL", Listen: "127.0.0.1:8443", InfoListen: "127.0.0.1:8080"},
			wantErr: false,
		},
		{
			name:    "local mode tolerates empty listen (gateway omits the proxy listener)",
			cfg:     config.Gateway{Control: "local", InfoListen: "127.0.0.1:8080"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkLocalModeBinds(&tt.cfg)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantContain != "" && !strings.Contains(err.Error(), tt.wantContain) {
				t.Fatalf("error %q missing %q", err.Error(), tt.wantContain)
			}
		})
	}
}
