package tunnels

// local_command tunnel: spawns an arbitrary command that exposes a
// local listener and proxies traffic to it. Covers cloud_sql_proxy,
// kubectl-port-forward-via-shell, and any future "we already have a
// CLI for this" upstream.
//
// Endpoint operators-edited HCL:
//
//   tunnel "local_command" "csql-prod" {
//     command       = ["cloud_sql_proxy", "--enable_iam_login",
//                      "--instances", "denosr-prod:us-central1:main-pg14=tcp:5432"]
//     listen        = "127.0.0.1:5432"
//     ready_probe   = "tcp"            # tcp | none
//     ready_timeout = "30s"
//     share         = "singleton"      # default
//     keepalive     = "5m"             # default
//     env           = { GOOGLE_APPLICATION_CREDENTIALS = "/run/secrets/gcp.json" }
//   }
//
// The plugin owns no addressing logic — it always dials the
// configured `listen`, ignoring whatever addr the dispatcher
// hands to Tunnel.Dial. That's the right behaviour for proxies
// like cloud_sql_proxy that already encode the upstream target
// in their argv.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// LocalCommandTunnel configures the tunnel runtime.
type LocalCommandTunnel struct {
	// Command is the argv vector to spawn for the tunnel process.
	Command []string `hcl:"command"`
	// Listen is the local address the spawned command exposes.
	Listen string `hcl:"listen"`
	// ReadyProbe is an optional TCP address to poll before the tunnel is ready.
	ReadyProbe string `hcl:"ready_probe,optional"`
	// ReadyTimeout overrides the default readiness wait duration.
	ReadyTimeout string `hcl:"ready_timeout,optional"`
	// Env adds environment variables to the spawned command.
	Env map[string]string `hcl:"env,optional"`

	// Share controls whether runtime instances are singleton, per-endpoint, or per-request.
	Share string `hcl:"share,optional"`
	// Keepalive keeps an idle tunnel runtime warm for the given duration.
	Keepalive string `hcl:"keepalive,optional"`
	// Via chains this tunnel through another tunnel.
	Via string `hcl:"via,optional"`
	// Credential references an optional credential block for the tunnel runtime.
	Credential string `hcl:"credential,optional"`
}

// TunnelCommon returns shared tunnel settings.
func (t *LocalCommandTunnel) TunnelCommon() config.TunnelCommon {
	return config.TunnelCommon{
		Share:      t.Share,
		Keepalive:  t.Keepalive,
		Via:        t.Via,
		Credential: t.Credential,
	}
}

// Sharing implements runtime.TunnelRuntime. local_command defaults to
// singleton — one process serves every endpoint that references it.
func (*LocalCommandTunnel) Sharing() runtime.TunnelSharing { return runtime.TunnelShareSingleton }

// Open implements runtime.TunnelRuntime. Spawns the configured
// command, waits for the readiness probe, and returns a handle whose
// Dial connects to the configured listen address.
func (t *LocalCommandTunnel) Open(ctx context.Context, host runtime.TunnelHost, _ runtime.Tunnel) (runtime.Tunnel, error) {
	if len(t.Command) == 0 {
		return nil, errors.New("local_command: command is empty")
	}
	if t.Listen == "" {
		return nil, errors.New("local_command: listen is empty")
	}
	readyTimeout := 30 * time.Second
	if t.ReadyTimeout != "" {
		d, err := time.ParseDuration(t.ReadyTimeout)
		if err != nil {
			return nil, fmt.Errorf("local_command: invalid ready_timeout %q: %w", t.ReadyTimeout, err)
		}
		readyTimeout = d
	}

	logger := host.Logger
	if logger == nil {
		logger = log.Default()
	}

	cmd := exec.Command(t.Command[0], t.Command[1:]...)
	if len(t.Env) > 0 {
		// Sort for deterministic env order in logs.
		keys := make([]string, 0, len(t.Env))
		for k := range t.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		env := cmd.Environ()
		for _, k := range keys {
			env = append(env, k+"="+t.Env[k])
		}
		cmd.Env = env
	}
	// Run the child in its own process group so we can kill the
	// whole tree on Close — many proxies fork helper processes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("local_command: spawn %q: %w", t.Command[0], err)
	}

	logger.Printf("local_command/%s: spawned pid %d (%v)", host.Name, cmd.Process.Pid, t.Command)

	rt := &localCommandTunnel{
		name:    host.Name,
		listen:  t.Listen,
		cmd:     cmd,
		logger:  logger,
		exited:  make(chan struct{}),
		dialer:  &net.Dialer{Timeout: 5 * time.Second},
		readyOK: false,
	}
	go rt.waitProcess()

	if t.ReadyProbe != "none" {
		probeCtx, cancel := context.WithTimeout(ctx, readyTimeout)
		defer cancel()
		if err := readinessTCP(probeCtx, t.Listen, 200*time.Millisecond); err != nil {
			_ = rt.Close()
			return nil, fmt.Errorf("local_command/%s: %w", host.Name, err)
		}
	}
	rt.readyOK = true
	return rt, nil
}

// localCommandTunnel is the live runtime handle the manager hands
// the dispatcher. Closed once when refcount==0 and idle elapses.
type localCommandTunnel struct {
	name    string
	listen  string
	cmd     *exec.Cmd
	logger  *log.Logger
	dialer  *net.Dialer
	exited  chan struct{}
	closed  sync.Once
	closeOK error
	readyOK bool
}

func (t *localCommandTunnel) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	if !t.readyOK {
		return nil, errors.New("local_command tunnel not ready")
	}
	return t.dialer.DialContext(ctx, network, t.listen)
}

// waitProcess reaps the child so kernel doesn't leave it as a
// zombie. If the process dies on its own (proxy crash) we log it;
// the manager will discover the dead tunnel on next Dial.
func (t *localCommandTunnel) waitProcess() {
	err := t.cmd.Wait()
	close(t.exited)
	if err != nil {
		t.logger.Printf("local_command/%s: child exited: %v", t.name, err)
	}
}

func (t *localCommandTunnel) Close() error {
	t.closed.Do(func() {
		if t.cmd.Process == nil {
			return
		}
		// SIGTERM the whole process group, give it 3s, then SIGKILL.
		pid := t.cmd.Process.Pid
		if pgid, err := syscall.Getpgid(pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = t.cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-t.exited:
		case <-time.After(3 * time.Second):
			t.logger.Printf("local_command/%s: SIGTERM ignored, sending SIGKILL", t.name)
			if pgid, err := syscall.Getpgid(pid); err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = t.cmd.Process.Kill()
			}
			<-t.exited
		}
	})
	return t.closeOK
}

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindTunnel,
		Type:    "local_command",
		New:     newer[LocalCommandTunnel](),
		Refs:    commonRefs,
		Build:   passthrough,
		Runtime: (*LocalCommandTunnel)(nil),
		Emit: func(body any, _ string, b *hclwrite.Body) {
			t := body.(*LocalCommandTunnel)
			if len(t.Command) > 0 {
				b.SetAttributeValue("command", config.StringListVal(t.Command))
			}
			if t.Listen != "" {
				b.SetAttributeValue("listen", cty.StringVal(t.Listen))
			}
			if t.ReadyProbe != "" {
				b.SetAttributeValue("ready_probe", cty.StringVal(t.ReadyProbe))
			}
			if t.ReadyTimeout != "" {
				b.SetAttributeValue("ready_timeout", cty.StringVal(t.ReadyTimeout))
			}
			if len(t.Env) > 0 {
				keys := make([]string, 0, len(t.Env))
				for k := range t.Env {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				vals := make(map[string]cty.Value, len(t.Env))
				for _, k := range keys {
					vals[k] = cty.StringVal(t.Env[k])
				}
				b.SetAttributeValue("env", cty.ObjectVal(vals))
			}
			emitCommon(b, t.TunnelCommon())
		},
	})
}
