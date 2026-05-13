package tunnels

// kubernetes_port_forward tunnel: shells out to `kubectl
// port-forward` to expose a pod (or service / selector / templated
// jump-pod) as a local TCP port. Four mutually-exclusive target
// modes:
//
//   pod      = "<name>"             existing pod by name
//   service  = "<name>"             existing service by name (kubectl
//                                   resolves targetPort)
//   selector = { app = "..." }      pick the first ready pod by label
//   template = <<EOT ... EOT>>      apply an operator-supplied Pod
//                                   manifest, port-forward to it, and
//                                   delete it on teardown
//
// HCL examples:
//
//   tunnel "kubernetes_port_forward" "ssh-jump" {
//     context = "arn:aws:eks:..."
//     pod     = "ssh-server"
//     port    = 22
//   }
//
//   tunnel "kubernetes_port_forward" "pg" {
//     context = "arn:aws:eks:..."
//     service = "postgres"
//     port    = 5432
//   }
//
//   tunnel "kubernetes_port_forward" "rds-jump" {
//     context = "arn:aws:eks:..."
//     template = <<-EOT
//       apiVersion: v1
//       kind: Pod
//       metadata: { generateName: rds-jump- }
//       spec:
//         containers:
//         - name: socat
//           image: alpine/socat
//           args: [TCP-LISTEN:5432,fork,reuseaddr, "TCP:rds.amazonaws.com:5432"]
//           ports: [{ containerPort: 5432 }]
//     EOT
//     port = 5432
//   }
//
// Authentication: whatever `kubectl` picks up — KUBECONFIG /
// ~/.kube/config, or in-cluster service-account token when the
// gateway runs as a pod. The `context` HCL field selects a named
// context; empty means the kubeconfig's current-context.
//
// Requires `kubectl` on PATH. Open returns a helpful error when it
// can't be found.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// KubernetesPortForwardTunnel configures the tunnel runtime.
type KubernetesPortForwardTunnel struct {
	// Context selects a kubeconfig context; empty uses the current context.
	Context string `hcl:"context,optional"`
	// Namespace selects the Kubernetes namespace for kubectl commands.
	Namespace string `hcl:"namespace,optional"`

	// Pod names an existing pod to port-forward to. Exactly one of pod,
	// service, selector, or template must be set.
	Pod string `hcl:"pod,optional"`
	// Service names a service to port-forward to.
	Service string `hcl:"service,optional"`
	// Selector matches a ready pod to port-forward to.
	Selector map[string]string `hcl:"selector,optional"`
	// Template is a pod manifest to apply and port-forward to.
	Template string `hcl:"template,optional"`

	// Port is the pod-side port the forwarder targets. For service
	// mode it's the *service* port; kubectl resolves the matching
	// targetPort.
	Port int `hcl:"port"`

	// Cleanup controls whether a template-created pod is deleted on tunnel
	// teardown. "delete" (default) is right for the common create-on-demand
	// case; "keep" disables deletion.
	Cleanup string `hcl:"cleanup,optional"`

	// Share controls whether runtime instances are singleton, per-endpoint, or per-request.
	Share string `hcl:"share,optional"`
	// Keepalive keeps an idle tunnel runtime warm for the given duration.
	Keepalive string `hcl:"keepalive,optional"`
	// Via chains kubectl access through another tunnel.
	Via string `hcl:"via,optional"`
	// Credential references an optional credential block for Kubernetes access.
	Credential string `hcl:"credential,optional"`
}

// TunnelCommon returns shared tunnel settings.
func (t *KubernetesPortForwardTunnel) TunnelCommon() config.TunnelCommon {
	return config.TunnelCommon{
		Share:      t.Share,
		Keepalive:  t.Keepalive,
		Via:        t.Via,
		Credential: t.Credential,
	}
}

// Sharing defaults to per_endpoint — each endpoint gets its own
// ephemeral local port; two endpoints sharing one tunnel block
// would collide on the local listener.
func (*KubernetesPortForwardTunnel) Sharing() runtime.TunnelSharing {
	return runtime.TunnelSharePerEndpoint
}

// Open resolves the target, starts a `kubectl port-forward`
// subprocess, and parses its stdout for the bound local port.
func (t *KubernetesPortForwardTunnel) Open(ctx context.Context, host runtime.TunnelHost, _ runtime.Tunnel) (runtime.Tunnel, error) {
	logger := host.Logger
	if logger == nil {
		logger = log.Default()
	}
	if err := t.validateModes(); err != nil {
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil, fmt.Errorf(
			"kubernetes_port_forward/%s: `kubectl` not found in $PATH — "+
				"install it (https://kubernetes.io/docs/tasks/tools/) and "+
				"make sure it's on the gateway's PATH",
			host.Name)
	}
	ns := t.Namespace
	if ns == "" {
		ns = "default"
	}
	rt := &kubernetesPortForwardTunnel{
		name:    host.Name,
		logger:  logger,
		ctx:     t.Context,
		ns:      ns,
		cleanup: t.Cleanup != "keep",
	}
	target, err := t.resolveTarget(ctx, rt)
	if err != nil {
		rt.cleanupCreatedPod(context.Background())
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	if err := rt.startPortForward(ctx, target, t.Port); err != nil {
		rt.cleanupCreatedPod(context.Background())
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	logger.Printf("kubernetes_port_forward/%s: forwarding %s/%s → %s",
		host.Name, ns, target, rt.localAddr)
	return rt, nil
}

// validateModes enforces exactly-one-of pod / service / selector /
// template, and that port is set.
func (t *KubernetesPortForwardTunnel) validateModes() error {
	modes := 0
	for _, set := range []bool{
		t.Pod != "",
		t.Service != "",
		len(t.Selector) > 0,
		t.Template != "",
	} {
		if set {
			modes++
		}
	}
	if modes != 1 {
		return errors.New("set exactly one of `pod`, `service`, `selector`, `template`")
	}
	if t.Port == 0 {
		return errors.New("`port` is required (pod-side port; for service mode, the service port)")
	}
	return nil
}

// resolveTarget returns the `kubectl port-forward` target spec
// (pod/NAME, svc/NAME, or the name of a freshly-created pod in
// template mode).
func (t *KubernetesPortForwardTunnel) resolveTarget(ctx context.Context, rt *kubernetesPortForwardTunnel) (string, error) {
	switch {
	case t.Pod != "":
		return "pod/" + t.Pod, nil
	case t.Service != "":
		return "svc/" + t.Service, nil
	case len(t.Selector) > 0:
		name, err := pickReadyPod(ctx, rt.ctx, rt.ns, t.Selector)
		if err != nil {
			return "", err
		}
		return "pod/" + name, nil
	case t.Template != "":
		doc, err := podFromTemplate(t.Template)
		if err != nil {
			return "", fmt.Errorf("template: %w", err)
		}
		name, err := rt.applyAndWait(ctx, doc)
		if err != nil {
			return "", err
		}
		return "pod/" + name, nil
	}
	return "", errors.New("no target mode set (validateModes should have caught this)")
}

// pickReadyPod runs `kubectl get pods -l SEL -o name
// --field-selector=status.phase=Running` and returns the first
// match. Ready is approximated by Running; kubectl's port-forward
// will fail loudly if the pod isn't actually accepting connections.
func pickReadyPod(ctx context.Context, kctx, ns string, selector map[string]string) (string, error) {
	args := kctlArgs(kctx, ns,
		"get", "pods",
		"-l", labelSelector(selector),
		"--field-selector=status.phase=Running",
		"-o", "name")
	out, err := runKubectl(ctx, args)
	if err != nil {
		return "", fmt.Errorf("list pods by selector %q: %w", labelSelector(selector), err)
	}
	lines := strings.Fields(strings.TrimSpace(out))
	if len(lines) == 0 {
		return "", fmt.Errorf("no running pods match selector %q in namespace %q",
			labelSelector(selector), ns)
	}
	// strip the "pod/" prefix kubectl prints with -o name
	return strings.TrimPrefix(lines[0], "pod/"), nil
}

// podDoc is the minimal slice of a Pod manifest the plugin needs
// to track an applied-from-template pod. The full YAML is passed
// verbatim to `kubectl create`.
type podDoc struct {
	kind, name, generate, raw string
}

// podFromTemplate parses just enough of a Pod manifest to validate
// kind/name and round-trip the raw YAML to `kubectl create`. Returns
// an error for non-Pod kinds and for templates missing both `name`
// and `generateName`.
func podFromTemplate(y string) (*podDoc, error) {
	var head struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name         string `yaml:"name"`
			GenerateName string `yaml:"generateName"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(y), &head); err != nil {
		return nil, fmt.Errorf("decode pod yaml: %w", err)
	}
	if head.Kind != "" && head.Kind != "Pod" {
		return nil, fmt.Errorf("template kind %q not supported (Pod only)", head.Kind)
	}
	if head.Metadata.Name == "" && head.Metadata.GenerateName == "" {
		return nil, fmt.Errorf("template must set metadata.name or metadata.generateName")
	}
	return &podDoc{
		kind:     head.Kind,
		name:     head.Metadata.Name,
		generate: head.Metadata.GenerateName,
		raw:      y,
	}, nil
}

// labelSelector renders {key: val} as a comma-joined key=val list.
// Stable order isn't required — kubectl treats the selector as a
// set.
func labelSelector(m map[string]string) string {
	out := ""
	for k, v := range m {
		if out != "" {
			out += ","
		}
		out += k + "=" + v
	}
	return out
}

// kctlArgs prepends --context and --namespace flags (when set) to
// the given kubectl arg vector.
func kctlArgs(kctx, ns string, args ...string) []string {
	out := []string{}
	if kctx != "" {
		out = append(out, "--context", kctx)
	}
	if ns != "" {
		out = append(out, "-n", ns)
	}
	return append(out, args...)
}

// runKubectl runs `kubectl ARGS...` and returns its stdout. Stderr
// is folded into the returned error on failure.
func runKubectl(ctx context.Context, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return string(out), nil
}

type kubernetesPortForwardTunnel struct {
	name   string
	logger *log.Logger

	ctx string // kubectl --context
	ns  string

	// createdPod, if non-empty, is the name of a pod the plugin
	// applied at Open and should delete on Close (when cleanup=true).
	createdPod string
	cleanup    bool

	pf        *exec.Cmd
	localAddr string
	once      sync.Once
}

// applyAndWait shells out to `kubectl create -f -` + `kubectl wait
// --for=condition=Ready`. Returns the resolved pod name (which may
// differ from doc.name when `generateName` is used).
func (t *kubernetesPortForwardTunnel) applyAndWait(ctx context.Context, doc *podDoc) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl",
		kctlArgs(t.ctx, t.ns, "create", "-f", "-", "-o", "name")...)
	cmd.Stdin = strings.NewReader(doc.raw)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("kubectl create: %s", strings.TrimSpace(stderr.String()))
	}
	name := strings.TrimPrefix(strings.TrimSpace(string(out)), "pod/")
	if name == "" {
		return "", fmt.Errorf("kubectl create returned empty name")
	}
	if t.cleanup {
		t.createdPod = name
	}
	t.logger.Printf("kubernetes_port_forward/%s: created pod %s/%s", t.name, t.ns, name)

	waitArgs := kctlArgs(t.ctx, t.ns,
		"wait", "--for=condition=Ready", "pod/"+name, "--timeout=2m")
	if _, err := runKubectl(ctx, waitArgs); err != nil {
		return name, fmt.Errorf("pod %s/%s never became ready: %w", t.ns, name, err)
	}
	return name, nil
}

// portForwardReady matches kubectl's "Forwarding from 127.0.0.1:NNNN
// -> ..." line. We grab NNNN as the bound local port.
var portForwardReady = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+) ->`)

// startPortForward boots `kubectl port-forward` in a child process,
// reads its stdout for the bound local port, and arranges for SIGTERM
// on Close. We isolate the child in its own process group so we can
// signal it (and any subprocesses) reliably.
func (t *kubernetesPortForwardTunnel) startPortForward(ctx context.Context, target string, podPort int) error {
	args := kctlArgs(t.ctx, t.ns,
		"port-forward", target, fmt.Sprintf(":%d", podPort),
		"--address=127.0.0.1")
	cmd := exec.Command("kubectl", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = io.Discard // kubectl writes the "Forwarding from" line to stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("kubectl port-forward: %w", err)
	}
	t.pf = cmd

	// Read stdout until we see the bound-port line or the process dies.
	ready := make(chan int, 1)
	failed := make(chan error, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if m := portForwardReady.FindStringSubmatch(s.Text()); m != nil {
				p, _ := strconv.Atoi(m[1])
				ready <- p
				_, _ = io.Copy(io.Discard, stdout) // drain
				return
			}
		}
		failed <- fmt.Errorf("port-forward exited before becoming ready")
	}()

	select {
	case p := <-ready:
		t.localAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
		return nil
	case err := <-failed:
		t.killPF()
		return err
	case <-ctx.Done():
		t.killPF()
		return ctx.Err()
	case <-time.After(30 * time.Second):
		t.killPF()
		return fmt.Errorf("port-forward never became ready (30s)")
	}
}

// killPF SIGTERMs the port-forward process group and reaps it. Best
// effort — we don't surface errors because Close paths already log.
func (t *kubernetesPortForwardTunnel) killPF() {
	if t.pf == nil || t.pf.Process == nil {
		return
	}
	_ = syscall.Kill(-t.pf.Process.Pid, syscall.SIGTERM)
	_ = t.pf.Wait()
}

func (t *kubernetesPortForwardTunnel) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	if t.localAddr == "" {
		return nil, fmt.Errorf("kubernetes_port_forward not ready")
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, t.localAddr)
}

func (t *kubernetesPortForwardTunnel) Close() error {
	t.once.Do(func() {
		t.killPF()
		t.cleanupCreatedPod(context.Background())
	})
	return nil
}

func (t *kubernetesPortForwardTunnel) cleanupCreatedPod(ctx context.Context) {
	if t.createdPod == "" {
		return
	}
	name := t.createdPod
	t.createdPod = ""
	t.logger.Printf("kubernetes_port_forward/%s: deleting pod %s/%s", t.name, t.ns, name)
	delCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := kctlArgs(t.ctx, t.ns, "delete", "pod/"+name, "--wait=false")
	if _, err := runKubectl(delCtx, args); err != nil {
		t.logger.Printf("kubernetes_port_forward/%s: delete pod failed: %v", t.name, err)
	}
}

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindTunnel,
		Type:    "kubernetes_port_forward",
		New:     newer[KubernetesPortForwardTunnel](),
		Refs:    commonRefs,
		Build:   passthrough,
		Runtime: (*KubernetesPortForwardTunnel)(nil),
		Emit: func(body any, _ string, b *hclwrite.Body) {
			t := body.(*KubernetesPortForwardTunnel)
			if t.Context != "" {
				b.SetAttributeValue("context", cty.StringVal(t.Context))
			}
			if t.Namespace != "" {
				b.SetAttributeValue("namespace", cty.StringVal(t.Namespace))
			}
			if t.Pod != "" {
				b.SetAttributeValue("pod", cty.StringVal(t.Pod))
			}
			if t.Service != "" {
				b.SetAttributeValue("service", cty.StringVal(t.Service))
			}
			if len(t.Selector) > 0 {
				vals := make(map[string]cty.Value, len(t.Selector))
				for k, v := range t.Selector {
					vals[k] = cty.StringVal(v)
				}
				b.SetAttributeValue("selector", cty.ObjectVal(vals))
			}
			if t.Template != "" {
				b.SetAttributeValue("template", cty.StringVal(t.Template))
			}
			if t.Cleanup != "" {
				b.SetAttributeValue("cleanup", cty.StringVal(t.Cleanup))
			}
			if t.Port != 0 {
				b.SetAttributeValue("port", cty.NumberIntVal(int64(t.Port)))
			}
			emitCommon(b, t.TunnelCommon())
		},
	})
}
