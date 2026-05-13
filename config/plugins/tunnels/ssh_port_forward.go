package tunnels

// ssh_port_forward tunnel: opens an SSH session to a bastion and
// uses `client.Dial` (the SSH equivalent of `ssh -L`) to forward
// each Tunnel.Dial through the encrypted SSH channel. Multiple
// concurrent dials share one SSH session.
//
// The plugin reuses the existing `credential "ssh"` type — the
// same paste of a private key authenticates either an `endpoint
// "ssh"` block (agent traffic) or an `ssh_port_forward` tunnel
// (upstream port-forwarding).
//
//   tunnel "ssh_port_forward" "deploy-prod-pg" {
//     bastion    = "bastion.deploy.example:22"
//     user       = "root"
//     credential = deploy-bastion       # credential "ssh" "deploy-bastion" {}
//     # Optional: chain through another tunnel that brings up the
//     # bastion in the first place (e.g. kubectl_portforward).
//     via        = deploy-prod-jump
//   }
//
// When `via` is set, the SSH client dials its TCP transport through
// `via.Dial` instead of `net.Dial` — that's how the deploy-nextgen
// pattern (kubectl port-forward → ssh-server pod → ssh -L to RDS)
// composes from two single-purpose plugins.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/crypto/ssh"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/sshproto"
	"github.com/denoland/clawpatrol/config/runtime"
)

// SSHPortForwardTunnel configures the tunnel runtime.
type SSHPortForwardTunnel struct {
	// Bastion is the SSH server host:port; required when via is unset.
	Bastion string `hcl:"bastion,optional"`
	// User is the SSH username for the bastion login.
	User string `hcl:"user"`

	// Share controls whether runtime instances are singleton, per-endpoint, or per-request.
	Share string `hcl:"share,optional"`
	// Keepalive keeps an idle tunnel runtime warm for the given duration.
	Keepalive string `hcl:"keepalive,optional"`
	// Via chains the SSH connection through another tunnel.
	Via string `hcl:"via,optional"`
	// Credential references an ssh credential block used for bastion authentication.
	Credential string `hcl:"credential"`
}

// TunnelCommon returns shared tunnel settings.
func (t *SSHPortForwardTunnel) TunnelCommon() config.TunnelCommon {
	return config.TunnelCommon{
		Share:      t.Share,
		Keepalive:  t.Keepalive,
		Via:        t.Via,
		Credential: t.Credential,
	}
}

// Sharing defaults to singleton — one SSH session multiplexes every
// dial through the bastion.
func (*SSHPortForwardTunnel) Sharing() runtime.TunnelSharing { return runtime.TunnelShareSingleton }

// Open opens the SSH session, dialing the bastion either directly
// or through the configured `via` tunnel.
func (t *SSHPortForwardTunnel) Open(ctx context.Context, host runtime.TunnelHost, via runtime.Tunnel) (runtime.Tunnel, error) {
	if t.User == "" {
		return nil, errors.New("ssh_port_forward: user is required")
	}
	if host.Credential == nil {
		return nil, errors.New("ssh_port_forward: credential is required")
	}
	authCred, ok := host.Credential.Body.(sshproto.AuthCredential)
	if !ok {
		return nil, fmt.Errorf("ssh_port_forward: credential %q is not an ssh credential (got %T)", host.Credential.Name, host.Credential.Body)
	}
	sec, err := host.SecretStore.Get(host.Credential.Name)
	if err != nil {
		return nil, fmt.Errorf("ssh_port_forward: secret %q: %w", host.Credential.Name, err)
	}
	creds, err := authCred.SSHAuth(sec)
	if err != nil {
		return nil, fmt.Errorf("ssh_port_forward: SSHAuth %q: %w", host.Credential.Name, err)
	}

	authMethods, err := buildAuthMethods(creds)
	if err != nil {
		return nil, fmt.Errorf("ssh_port_forward: %w", err)
	}
	hostKey, err := buildHostKeyCallback(creds.HostPubkey)
	if err != nil {
		return nil, fmt.Errorf("ssh_port_forward: %w", err)
	}

	bastionAddr := t.Bastion
	if via != nil {
		// When chained, the underlying tunnel handles the network
		// hop; the SSH client just needs *some* TCP destination
		// for its handshake. Plugins like kubernetes_port_forward
		// ignore the addr and dial their own listener anyway.
		if bastionAddr == "" {
			bastionAddr = "via:22"
		}
	} else if bastionAddr == "" {
		return nil, errors.New("ssh_port_forward: bastion is required when via is unset")
	}

	logger := host.Logger
	if logger == nil {
		logger = log.Default()
	}

	dialBastion := func(ctx context.Context) (net.Conn, error) {
		if via != nil {
			return via.Dial(ctx, "tcp", bastionAddr)
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		return d.DialContext(ctx, "tcp", bastionAddr)
	}

	netConn, err := dialBastion(ctx)
	if err != nil {
		return nil, fmt.Errorf("ssh_port_forward: dial bastion %q: %w", bastionAddr, err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            authMethods,
		HostKeyCallback: hostKey,
		Timeout:         15 * time.Second,
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(netConn, bastionAddr, clientCfg)
	if err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("ssh_port_forward: handshake to %q: %w", bastionAddr, err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	logger.Printf("ssh_port_forward/%s: connected to %s as %q", host.Name, bastionAddr, t.User)
	return &sshPortForwardTunnel{
		name:   host.Name,
		client: client,
		logger: logger,
	}, nil
}

type sshPortForwardTunnel struct {
	name   string
	client *ssh.Client
	logger *log.Logger
	once   sync.Once
}

// Dial uses the SSH session's Dial — opens a new tunneled TCP
// channel through the bastion to addr (resolved on the bastion
// side, which is exactly what we want for hostnames that are only
// reachable from the bastion's network).
func (t *sshPortForwardTunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.client == nil {
		return nil, errors.New("ssh_port_forward tunnel closed")
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := t.client.Dial(network, addr)
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *sshPortForwardTunnel) Close() error {
	var err error
	t.once.Do(func() {
		if t.client != nil {
			err = t.client.Close()
			t.client = nil
		}
	})
	return err
}

// buildAuthMethods translates Creds into the ssh.AuthMethod list
// the client uses during handshake. Private key wins over password
// when both are set.
func buildAuthMethods(creds sshproto.Creds) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(creds.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if creds.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(creds.PrivateKey, []byte(creds.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(creds.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if creds.Password != "" {
		methods = append(methods, ssh.Password(creds.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("ssh credential: neither private_key nor password set")
	}
	return methods, nil
}

// buildHostKeyCallback returns a ssh.HostKeyCallback. When
// host_pubkey is set, the upstream host is pinned against it;
// otherwise the callback accepts any key and trust derives from
// the underlying transport (the WG tunnel + the via-chain).
func buildHostKeyCallback(pubkey string) (ssh.HostKeyCallback, error) {
	if pubkey == "" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	expected, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
	if err != nil {
		return nil, fmt.Errorf("parse host_pubkey: %w", err)
	}
	want := expected.Marshal()
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if !bytesEqual(key.Marshal(), want) {
			return errors.New("ssh host key mismatch — pinned host_pubkey rejected the upstream")
		}
		return nil
	}, nil
}

// bytesEqual is a small dep-free byte slice equal — keeps the
// import set focused.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func init() {
	config.Register(&config.Plugin{
		Kind: config.KindTunnel,
		Type: "ssh_port_forward",
		New:  newer[SSHPortForwardTunnel](),
		Refs: []config.RefSpec{
			{Path: "Via", Kind: config.KindTunnel, Optional: true},
			{Path: "Credential", Kind: config.KindCredential, Optional: false},
		},
		Build:   passthrough,
		Runtime: (*SSHPortForwardTunnel)(nil),
		Emit: func(body any, _ string, b *hclwrite.Body) {
			t := body.(*SSHPortForwardTunnel)
			if t.Bastion != "" {
				b.SetAttributeValue("bastion", cty.StringVal(t.Bastion))
			}
			b.SetAttributeValue("user", cty.StringVal(t.User))
			emitCommon(b, t.TunnelCommon())
		},
	})
}
