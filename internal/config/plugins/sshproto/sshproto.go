// Package sshproto holds the protocol-specific contract that bridges
// the SSH endpoint plugin and the SSH credential plugin. Lives in
// config/plugins/ rather than config/runtime/ so the runtime stays
// generic — runtime only knows about the cross-protocol shapes
// (HTTP / Postgres / TLS / ConnEndpoint) and discovers protocol
// extensions like this one through the AcceptCredentialRuntime hook.
//
// Both plugins import this package — the credential side declares it
// satisfies AuthCredential, the endpoint side type-asserts against
// it. There is no other consumer.
package sshproto

import (
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Creds is the materialised view an SSH credential hands to the SSH
// endpoint runtime. The credential carries only auth material — the
// upstream username comes from the agent (whatever the SSH client
// sent in the connect line). PrivateKey is the raw PEM bytes (PKCS#1,
// PKCS#8 or OpenSSH format — golang.org/x/crypto/ssh.ParsePrivateKey*
// handles all three). HostPubkey, when non-empty, is a single-line
// authorized_keys-style entry the endpoint pins for upstream
// verification (matches `ssh-keyscan` output).
type Creds struct {
	PrivateKey []byte
	Passphrase string
	Password   string
	HostPubkey string
}

// AuthCredential is what the SSH endpoint runtime needs from a
// credential plugin to authenticate upstream on the agent's behalf.
// The credential never sees the agent connection — it just returns
// the material; the endpoint runtime drives the upstream handshake.
// Mirrors the postgres SCRAM-offload split.
type AuthCredential interface {
	SSHAuth(sec runtime.Secret) (Creds, error)
}

// Teach the runtime's credential checker about AuthCredential so
// plugins implementing it pass init-time validation without runtime
// having to import this package.
func init() {
	runtime.AcceptCredentialRuntime(func(p *config.Plugin) bool {
		_, ok := p.Runtime.(AuthCredential)
		return ok
	})
}
