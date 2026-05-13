package tunnels

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/denoland/clawpatrol/config/plugins/sshproto"
	cruntime "github.com/denoland/clawpatrol/config/runtime"
)

// fakeSSHCred satisfies the sshproto.AuthCredential interface
// runtime tests need without dragging in the real credential plugin.
type fakeSSHCred struct{ creds sshproto.Creds }

func (f *fakeSSHCred) SSHAuth(_ cruntime.Secret) (sshproto.Creds, error) {
	return f.creds, nil
}

// fakeSecretStore returns an empty Secret for any name — the
// fakeSSHCred ignores it anyway because it stashes the creds in
// the struct, not in the env.
type fakeSecretStore struct{}

func (fakeSecretStore) Get(_ string) (cruntime.Secret, error) {
	return cruntime.Secret{}, nil
}

// inProcessSSHServer boots a tiny SSH server that accepts the
// configured pubkey and serves only the "direct-tcpip" channel
// type — i.e. it implements `ssh -L`-style forwarding to whatever
// target the client requests. Returns the listen address + a
// cleanup. On each forward, dials the requested target and bridges
// bytes; that's enough for the tunnel test to verify Dial reaches
// a real listener through the SSH session.
func inProcessSSHServer(t *testing.T, pubKey ssh.PublicKey, hostSigner ssh.Signer) (addr string, cleanup func()) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytesEqual(k.Marshal(), pubKey.Marshal()) {
				return nil, errors.New("unauthorized key")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveSSH(conn, cfg)
		}
	}()
	return l.Addr().String(), func() {
		_ = l.Close()
		<-done
	}
}

func serveSSH(rawConn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = rawConn.Close() }()
	_, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		// direct-tcpip extra data is RFC 4254 §7.2:
		//   string  target host
		//   uint32  target port
		//   string  origin
		//   uint32  origin port
		var payload struct {
			Target     string
			TargetPort uint32
			Origin     string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		// Dial the requested target and bridge.
		target := net.JoinHostPort(payload.Target, itoaPort(int(payload.TargetPort)))
		up, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			_ = ch.Close()
			continue
		}
		go bridge(ch, up)
	}
}

func bridge(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); _ = a.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); _ = b.Close() }()
	wg.Wait()
}

func itoaPort(p int) string {
	// avoid strconv import bloat for this trivial use
	if p == 0 {
		return "0"
	}
	var buf [6]byte
	n := len(buf)
	for p > 0 {
		n--
		buf[n] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[n:])
}

// TestSSHPortForward boots an SSH server, points the tunnel at it,
// confirms Dial routes through to a target listener, and tears
// the session down on Close.
func TestSSHPortForward(t *testing.T) {
	// Generate a client keypair + a host key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	clientPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("client pub: %v", err)
	}
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("hostkey: %v", err)
	}
	_ = hostPub
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	bastionAddr, cleanup := inProcessSSHServer(t, clientPub, hostSigner)
	defer cleanup()

	// Target listener we'll forward to.
	targetL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer func() { _ = targetL.Close() }()
	go func() {
		for {
			c, err := targetL.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
	}()

	// Marshal the private key as PEM so the credential parses it.
	pemBlk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, pemBlk); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	keyBytes := keyBuf.Bytes()

	cred := &fakeSSHCred{creds: sshproto.Creds{PrivateKey: keyBytes}}

	tn := &SSHPortForwardTunnel{
		Bastion:    bastionAddr,
		User:       "test",
		Credential: "fake",
	}

	host := cruntime.TunnelHost{
		Name:        "test",
		SecretStore: fakeSecretStore{},
		Credential: &cruntime.TunnelCredential{
			Name: "fake",
			Type: "ssh",
			Body: cred,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rt, err := tn.Open(ctx, host, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rt.Close() }()

	// Dial via SSH session — uses the bastion's `direct-tcpip`
	// channel to reach our target listener. Use `clientSigner`
	// indirectly (already loaded above).
	_ = clientSigner
	conn, err := rt.Dial(ctx, "tcp", targetL.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 5)
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Errorf("read %q, want hello", got)
	}
}
