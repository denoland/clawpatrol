package main

import "testing"

func TestWGClientEndpoint(t *testing.T) {
	cases := []struct {
		name      string
		wgEnd     string
		publicURL string
		want      string
		wantErr   bool
	}{
		{
			name:      "empty wg_endpoint uses public_url host + default port",
			wgEnd:     "",
			publicURL: "https://gw.example.com:9080",
			want:      "gw.example.com:51820",
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
			got, err := wgClientEndpoint(tc.wgEnd, tc.publicURL)
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
