package config_test

import (
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestNormalizePublicURLForOIDC(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "trims trailing slashes", in: "https://clawpatrol.example.com///", want: "https://clawpatrol.example.com"},
		{name: "keeps path", in: "https://example.com/clawpatrol/", want: "https://example.com/clawpatrol"},
		{name: "rejects empty", in: "", wantErr: true},
		{name: "rejects http", in: "http://clawpatrol.example.com", wantErr: true},
		{name: "rejects missing scheme", in: "clawpatrol.example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := config.NormalizePublicURLForOIDC(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizePublicURLForOIDC(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
