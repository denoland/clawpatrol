package endpoints

import (
	"testing"

	"github.com/denoland/clawpatrol/config"
)

// pickSSHCredential covers the multi-credential dispatch contract:
// * exact-user match wins
// * catchall (no Placeholder) is the fallback
// * with no credentials → nil
// * single no-Placeholder entry → that entry, regardless of agent user
// * no match + no fallback → nil
func TestPickSSHCredential(t *testing.T) {
	mk := func(placeholder, name string) *config.CompiledCredential {
		return &config.CompiledCredential{
			Placeholder: placeholder,
			Credential: &config.Entity{
				Symbol: &config.Symbol{Kind: config.KindCredential, Type: "ssh", Name: name},
			},
		}
	}
	cases := []struct {
		name  string
		creds []*config.CompiledCredential
		user  string
		want  string // expected credential name; "" for nil
	}{
		{"empty list", nil, "anybody", ""},
		{"singular catchall — matches any user", []*config.CompiledCredential{mk("", "default")}, "anybody", "default"},
		{"singular catchall — empty user", []*config.CompiledCredential{mk("", "default")}, "", "default"},
		{
			"multi: exact match",
			[]*config.CompiledCredential{
				mk("root", "root-cred"),
				mk("deploy", "deploy-cred"),
				mk("", "fallback-cred"),
			},
			"deploy",
			"deploy-cred",
		},
		{
			"multi: fallback when no exact match",
			[]*config.CompiledCredential{
				mk("root", "root-cred"),
				mk("deploy", "deploy-cred"),
				mk("", "fallback-cred"),
			},
			"alice",
			"fallback-cred",
		},
		{
			"multi: no match + no fallback → nil",
			[]*config.CompiledCredential{
				mk("root", "root-cred"),
				mk("deploy", "deploy-cred"),
			},
			"alice",
			"",
		},
		{
			"multi: matched user takes precedence over catchall order",
			[]*config.CompiledCredential{
				mk("", "fallback-cred"),
				mk("root", "root-cred"),
			},
			"root",
			"root-cred",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep := &config.CompiledEndpoint{Credentials: c.creds}
			got := pickSSHCredential(ep, c.user)
			if c.want == "" {
				if got != nil {
					t.Fatalf("expected nil; got %q", got.Credential.Symbol.Name)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %q; got nil", c.want)
			}
			if got.Credential.Symbol.Name != c.want {
				t.Fatalf("expected %q; got %q", c.want, got.Credential.Symbol.Name)
			}
		})
	}
}
