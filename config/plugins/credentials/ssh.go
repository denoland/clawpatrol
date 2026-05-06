package credentials

// ssh credential: the wire-protocol user + key/password the SSH
// endpoint runtime uses when terminating upstream auth on the agent's
// behalf. The agent never sees the upstream auth challenge; the
// gateway accepts whatever the agent's SSH client offers (WG is the
// trust boundary) and replays the credential's material upstream.
//
// Material is split across slots so operators can paste a multi-line
// PEM into one textarea and a single-line passphrase into another:
//
//   private_key  multi-line   OpenSSH / PKCS#8 / PKCS#1 PEM
//   passphrase   single-line  optional, decrypts private_key
//   password     single-line  optional, used when no key is set
//   host_pubkey  single-line  optional, ssh-keyscan-style line for
//                             upstream host pinning
//
// At least one of (private_key, password) must be filled at runtime —
// the endpoint surfaces a clear error to the agent if both are empty.

import (
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/sshproto"
	"github.com/denoland/clawpatrol/config/runtime"
)

type SSHCredential struct {
	User string `hcl:"user,optional"`
}

// SSHAuth implements sshproto.AuthCredential. Returns the raw
// material; the SSH endpoint runtime parses keys via
// golang.org/x/crypto/ssh and surfaces parse errors with line
// context.
func (s *SSHCredential) SSHAuth(sec runtime.Secret) (sshproto.Creds, error) {
	creds := sshproto.Creds{User: s.User}
	if v, ok := sec.Extras["private_key"]; ok {
		creds.PrivateKey = []byte(v)
	}
	if v, ok := sec.Extras["passphrase"]; ok {
		creds.Passphrase = v
	}
	if v, ok := sec.Extras["password"]; ok {
		creds.Password = v
	}
	if v, ok := sec.Extras["host_pubkey"]; ok {
		creds.HostPubkey = v
	}
	return creds, nil
}

func (*SSHCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{
			Name:        "private_key",
			Label:       "SSH private key (PEM)",
			Multiline:   true,
			Description: "OpenSSH / PKCS#8 / PKCS#1 format. Leave empty to use password auth instead.",
		},
		{
			Name:        "passphrase",
			Label:       "Key passphrase (optional)",
			Description: "Required only when the private key is encrypted.",
		},
		{
			Name:        "password",
			Label:       "SSH password (optional)",
			Description: "Used when no private key is provided.",
		},
		{
			Name:        "host_pubkey",
			Label:       "Upstream host pubkey (optional)",
			Description: "Single ssh-keyscan-style line. When set, the gateway pins the upstream's host key against it; otherwise the WG tunnel is the trust boundary.",
		},
	}
}

func init() {
	var _ sshproto.AuthCredential = (*SSHCredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "ssh",
		New:     newer[SSHCredential](),
		Runtime: (*SSHCredential)(nil),
		Build:   passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*SSHCredential)
			if v.User != "" {
				b.SetAttributeValue("user", cty.StringVal(v.User))
			}
		},
	})
}
