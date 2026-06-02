package endpoints

// End-to-end tests for ssh.stdin pre-gating. They drive a real
// golang.org/x/crypto/ssh client (and, when available, the real
// OpenSSH `ssh` binary) through the gateway's HandleConn into a real
// in-process upstream ssh server — no Docker, hermetic, CI-friendly.
//
// The blank imports register the plugins config.Compile needs to build
// a policy with an ssh endpoint + ssh_key credential + ssh.stdin rules
// (the ssh endpoint itself registers via this package's own init).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/denoland/clawpatrol/internal/config"
	cruntime "github.com/denoland/clawpatrol/internal/config/runtime"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/credentials"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/ssh"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/rules"
)

// ── upstream ssh server (records what each session actually ran) ──────

type upstreamSession struct {
	command string
	stdin   []byte
}

type fakeUpstream struct {
	addr     string
	mu       sync.Mutex
	sessions []upstreamSession
}

func (u *fakeUpstream) record(s upstreamSession) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.sessions = append(u.sessions, s)
}

func (u *fakeUpstream) recorded() []upstreamSession {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamSession(nil), u.sessions...)
}

func startFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("upstream key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("upstream signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		NoClientAuth:     true,
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil },
	}
	cfg.AddHostKey(signer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	u := &fakeUpstream{addr: l.Addr().String()}
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); u.serve(conn, cfg) }()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	return u
}

func (u *fakeUpstream) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go u.handleSession(ch, chReqs)
	}
}

// handleSession runs the agent's command once shell/exec arrives:
// reads stdin to EOF, records (command, stdin), echoes "stdin=<bytes>"
// to stdout, and exits 0. When the gateway denies before forwarding,
// the request stream closes with no exec/shell — nothing is recorded.
func (u *fakeUpstream) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for r := range reqs {
		switch r.Type {
		case "exec", "shell":
			command := "<shell>"
			if r.Type == "exec" {
				var p struct{ Command string }
				_ = ssh.Unmarshal(r.Payload, &p)
				command = p.Command
			}
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			data, _ := io.ReadAll(ch) // stdin until gateway CloseWrites
			u.record(upstreamSession{command: command, stdin: data})
			_, _ = fmt.Fprintf(ch, "stdin=%s", string(data))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		case "pty-req", "env", "window-change":
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
		default:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
}

// ── gateway harness ───────────────────────────────────────────────────

type eventSink struct {
	mu     sync.Mutex
	events []cruntime.ConnEvent
}

func (e *eventSink) add(ev cruntime.ConnEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
}

func (e *eventSink) all() []cruntime.ConnEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]cruntime.ConnEvent(nil), e.events...)
}

func (e *eventSink) hasAction(action string) bool {
	for _, ev := range e.all() {
		if ev.Action == action {
			return true
		}
	}
	return false
}

type inMemBlobs map[string]map[string][]byte

func (s inMemBlobs) Get(kind, name string) ([]byte, bool, error) {
	if m, ok := s[kind]; ok {
		if b, ok := m[name]; ok {
			return b, true, nil
		}
	}
	return nil, false, nil
}

func (s inMemBlobs) Put(kind, name string, data []byte) error {
	if s[kind] == nil {
		s[kind] = map[string][]byte{}
	}
	s[kind][name] = data
	return nil
}

type mapSecrets map[string]cruntime.Secret

func (m mapSecrets) Get(name string) (cruntime.Secret, error) { return m[name], nil }

const e2eGatewayPrefix = `gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
`

func compileE2EPolicy(t *testing.T, hcl string) *config.CompiledPolicy {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(e2eGatewayPrefix+hcl), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return policy
}

// startGateway compiles the policy, stands up the upstream, and serves
// the gateway on a localhost listener. Returns the gateway address, the
// event sink, and the upstream recorder.
func startGateway(t *testing.T, hcl string) (addr string, ev *eventSink, up *fakeUpstream) {
	t.Helper()
	policy := compileE2EPolicy(t, hcl)
	ep := policy.Endpoints["build-host"]
	if ep == nil {
		t.Fatalf("policy has no build-host endpoint")
	}
	up = startFakeUpstream(t)
	ev = &eventSink{}
	secrets := mapSecrets{"build-key": cruntime.Secret{Extras: map[string]string{"password": "pw"}}}
	blobs := inMemBlobs{}
	rt := &SSHEndpointRuntime{}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("gateway listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = rt.HandleConn(ctx, &cruntime.ConnHandle{
					Conn:     conn,
					Endpoint: ep,
					Policy:   policy,
					Profile:  "default",
					PeerIP:   "100.64.0.9",
					Secrets:  secrets,
					Blobs:    blobs,
					Emit:     ev.add,
					DialUpstream: func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, up.addr)
					},
				})
			}()
		}
	}()
	t.Cleanup(func() { cancel(); _ = l.Close(); wg.Wait() })
	return l.Addr().String(), ev, up
}

func dialAgent(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password("anything")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// runExec runs one `command` with the given stdin via a fresh session
// and returns the combined stdout/stderr plus any wait error. It drains
// stdout fully BEFORE Wait (the StdoutPipe idiom) so the exit-status
// can't race ahead of the output capture.
func runExec(t *testing.T, c *ssh.Client, command, stdin string) (string, error) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var errBuf bytes.Buffer
	sess.Stderr = &errBuf
	sess.Stdin = strings.NewReader(stdin)
	if err := sess.Start(command); err != nil {
		return errBuf.String(), err
	}
	outBytes, _ := io.ReadAll(stdout)
	werr := sess.Wait()
	return string(outBytes) + errBuf.String(), werr
}

// blockSecretHCL: a single ssh.stdin deny rule. A non-matching action
// falls through to implicit allow. Presence of the stdin rule flips the
// endpoint onto the stdin-gated splice path.
const blockSecretHCL = `
endpoint "ssh" "build-host" {
  hosts = ["build.example.com:2222"]
}
credential "ssh_key" "build-key" {
  endpoint = ssh.build-host
}
rule "block-secret" {
  endpoint  = ssh.build-host
  condition = "ssh.stdin.contains('SECRET')"
  verdict   = "deny"
  reason    = "secret material in stdin"
}
profile "default" {
  credentials = [ssh_key.build-key]
}
`

func TestE2EStdinInspectsTruncatableSet(t *testing.T) {
	policy := compileE2EPolicy(t, blockSecretHCL)
	if !policy.Endpoints["build-host"].InspectsTruncatable {
		t.Fatal("expected InspectsTruncatable=true when a rule reads ssh.stdin")
	}
	// A policy with no stdin rule must NOT flip the flag (fast path).
	noStdin := strings.Replace(blockSecretHCL,
		`condition = "ssh.stdin.contains('SECRET')"`,
		`condition = "ssh.verb == 'exec'"`, 1)
	p2 := compileE2EPolicy(t, noStdin)
	if p2.Endpoints["build-host"].InspectsTruncatable {
		t.Fatal("expected InspectsTruncatable=false when no rule reads ssh.stdin")
	}
}

func TestE2EStdinAllowForwardsBytes(t *testing.T) {
	addr, ev, up := startGateway(t, blockSecretHCL)
	c := dialAgent(t, addr)

	out, err := runExec(t, c, "cat", "hello world\n")
	if err != nil {
		t.Fatalf("allowed exec failed: %v out=%q", err, out)
	}
	if !strings.Contains(out, "stdin=hello world") {
		t.Errorf("output %q missing forwarded stdin", out)
	}
	sessions := up.recorded()
	if len(sessions) != 1 {
		t.Fatalf("upstream sessions = %d, want 1", len(sessions))
	}
	if sessions[0].command != "cat" || string(sessions[0].stdin) != "hello world\n" {
		t.Errorf("upstream got %+v; want cmd=cat stdin=%q", sessions[0], "hello world\n")
	}
	if !ev.hasAction("allow") {
		t.Errorf("expected an allow event; got %+v", ev.all())
	}
}

func TestE2EStdinDenyNeverRuns(t *testing.T) {
	addr, ev, up := startGateway(t, blockSecretHCL)
	c := dialAgent(t, addr)

	out, err := runExec(t, c, "cat", "here is the SECRET value\n")
	if err == nil {
		t.Errorf("expected denied exec to fail; out=%q", out)
	}
	if got := up.recorded(); len(got) != 0 {
		t.Fatalf("upstream ran %d sessions on a denied stdin; want 0: %+v", len(got), got)
	}
	if !ev.hasAction("deny") {
		t.Errorf("expected a deny event; got %+v", ev.all())
	}
}

// blockRmHCL pairs an ssh.stdin rule (to force the stdin-gated path)
// with a command rule, proving command rules still pre-gate (deny
// BEFORE the request reaches upstream) on the stdin path.
const blockRmHCL = `
endpoint "ssh" "build-host" {
  hosts = ["build.example.com:2222"]
}
credential "ssh_key" "build-key" {
  endpoint = ssh.build-host
}
rule "block-secret" {
  endpoint  = ssh.build-host
  condition = "ssh.stdin.contains('SECRET')"
  verdict   = "deny"
}
rule "block-rm" {
  endpoint  = ssh.build-host
  condition = "ssh.verb == 'exec' && ssh.command.startsWith('rm ')"
  verdict   = "deny"
  reason    = "no rm"
}
profile "default" {
  credentials = [ssh_key.build-key]
}
`

func TestE2ECommandPreGateOnStdinPath(t *testing.T) {
	addr, ev, up := startGateway(t, blockRmHCL)
	c := dialAgent(t, addr)

	_, err := runExec(t, c, "rm -rf /tmp/whatever", "")
	if err == nil {
		t.Error("expected denied command to fail")
	}
	if got := up.recorded(); len(got) != 0 {
		t.Fatalf("denied command reached upstream (%d sessions); pre-gate broken", len(got))
	}
	if !ev.hasAction("deny") {
		t.Errorf("expected a deny event; got %+v", ev.all())
	}
}

// fastPathHCL has no stdin rule → InspectsTruncatable=false → the
// unchanged proxyChannel splice. Run several execs in succession to
// guard the graceful-close (~10% blank-output) flake invariant.
const fastPathHCL = `
endpoint "ssh" "build-host" {
  hosts = ["build.example.com:2222"]
}
credential "ssh_key" "build-key" {
  endpoint = ssh.build-host
}
rule "allow-exec" {
  endpoint  = ssh.build-host
  condition = "ssh.verb == 'exec'"
  verdict   = "allow"
}
profile "default" {
  credentials = [ssh_key.build-key]
}
`

func TestE2EFastPathUnchanged(t *testing.T) {
	addr, _, up := startGateway(t, fastPathHCL)
	c := dialAgent(t, addr)
	for i := 0; i < 8; i++ {
		out, err := runExec(t, c, "echo", fmt.Sprintf("run-%d\n", i))
		if err != nil {
			t.Fatalf("run %d failed: %v out=%q", i, err, out)
		}
		if !strings.Contains(out, fmt.Sprintf("stdin=run-%d", i)) {
			t.Errorf("run %d: output %q missing stdin", i, out)
		}
	}
	if len(up.recorded()) != 8 {
		t.Errorf("upstream sessions = %d, want 8", len(up.recorded()))
	}
}

// blockPtyHCL blocks interactive terminals AND inspects stdin, so a pty
// request must still bail to the envelope path and be refused even on
// the stdin-gated splice.
const blockPtyHCL = `
endpoint "ssh" "build-host" {
  hosts = ["build.example.com:2222"]
}
credential "ssh_key" "build-key" {
  endpoint = ssh.build-host
}
rule "block-secret" {
  endpoint  = ssh.build-host
  condition = "ssh.stdin.contains('SECRET')"
  verdict   = "deny"
}
rule "no-pty" {
  endpoint  = ssh.build-host
  condition = "ssh.verb == 'pty'"
  verdict   = "deny"
  reason    = "no terminals"
}
profile "default" {
  credentials = [ssh_key.build-key]
}
`

func TestE2EPtyBailOnStdinPath(t *testing.T) {
	addr, ev, _ := startGateway(t, blockPtyHCL)
	c := dialAgent(t, addr)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestPty("xterm", 40, 80, ssh.TerminalModes{}); err == nil {
		t.Error("expected pty request to be denied on the stdin-gated endpoint")
	}
	if !ev.hasAction("deny") {
		t.Errorf("expected a pty deny event; got %+v", ev.all())
	}
}

// TestE2ERealOpenSSHClient drives the actual OpenSSH `ssh` binary (not
// the Go client, which orders the exec reply / stdin differently)
// through the gateway. Skipped when the binary is absent so CI without
// OpenSSH still passes.
func TestE2ERealOpenSSHClient(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no openssh client available")
	}
	addr, _, up := startGateway(t, blockSecretHCL)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"deploy@" + host,
	}

	run := func(stdin, command string) (string, error) {
		cmd := exec.Command(sshBin, append(append([]string{}, base...), command)...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := run("hello from openssh\n", "cat")
	if err != nil {
		t.Fatalf("allowed openssh exec failed: %v out=%q", err, out)
	}
	if !strings.Contains(out, "stdin=hello from openssh") {
		t.Errorf("allowed output %q missing forwarded stdin", out)
	}

	out2, err2 := run("this carries a SECRET\n", "cat")
	if err2 == nil {
		t.Errorf("expected denied openssh exec to fail; out=%q", out2)
	}

	sessions := up.recorded()
	if len(sessions) != 1 {
		t.Fatalf("upstream ran %d sessions; want exactly 1 (deny must not reach upstream): %+v", len(sessions), sessions)
	}
	if string(sessions[0].stdin) != "hello from openssh\n" {
		t.Errorf("upstream stdin = %q; want the allowed payload", sessions[0].stdin)
	}
}
