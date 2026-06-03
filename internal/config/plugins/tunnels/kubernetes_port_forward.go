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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"go.yaml.in/yaml/v3"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// KubernetesPortForwardTunnel configures the tunnel runtime.
type KubernetesPortForwardTunnel struct {
	// Context selects a kubeconfig context; empty uses the current
	// context. Ignored when Server is set (the plugin builds its own
	// per-tunnel kubeconfig).
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
	// case; "keep" disables deletion. Created pods are stamped with
	// `clawpatrol.dev/managed-by=clawpatrol` and `clawpatrol.dev/tunnel=<name>`
	// labels; unless cleanup is "keep", a startup sweep deletes any pod
	// carrying those labels that a previous daemon lifetime left behind
	// (e.g. after a crash skipped graceful teardown).
	Cleanup string `hcl:"cleanup,optional"`

	// Server is the Kubernetes apiserver URL. When set the plugin
	// writes a per-tunnel kubeconfig (server + ca_cert + bearer minted
	// from the bound credential) and invokes kubectl with --kubeconfig
	// pointing at it; no external kubeconfig or KUBECONFIG env is
	// needed. The Context field is then ignored.
	Server string `hcl:"server,optional"`
	// CACert is the cluster CA PEM. Supports `<<file:path.pem>>` for
	// out-of-line storage; the loader inlines the file contents.
	// Required when Server is set against EKS (the apiserver presents
	// a per-cluster CA that no system trust store carries).
	CACert string `hcl:"ca_cert,optional"`
	// ClusterName is the EKS cluster name, used by an aws_credential
	// to scope the STS presign (sets the X-K8s-Aws-Id header). Only
	// meaningful alongside Server + an aws_credential.
	ClusterName string `hcl:"cluster_name,optional"`
	// Region is the AWS region the EKS cluster lives in; SigV4 needs
	// it. Only meaningful alongside Server + an aws_credential.
	Region string `hcl:"region,optional"`

	// Share controls whether runtime instances are singleton, per-endpoint, or per-request.
	Share string `hcl:"share,optional"`
	// Keepalive keeps an idle tunnel runtime warm for the given duration.
	Keepalive string `hcl:"keepalive,optional"`
	// Via chains kubectl access through another tunnel.
	Via string `hcl:"via,optional"`
	// Credential references an optional credential block for Kubernetes access.
	Credential string `hcl:"credential,optional"`
}

// FileIncludeFields tells the loader to inline `<<file:NAME>>` markers
// in ca_cert. Operators reference the cluster CA by filename so the
// PEM stays out of the policy file.
func (t *KubernetesPortForwardTunnel) FileIncludeFields() []config.FileIncludeField {
	return []config.FileIncludeField{
		{Get: func() string { return t.CACert }, Set: func(v string) { t.CACert = v }},
	}
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
	if err := t.validateModes(); err != nil {
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	if err := lookupKubectl(); err != nil {
		return nil, fmt.Errorf(
			"kubernetes_port_forward/%s: `kubectl` not found in $PATH — "+
				"install it (https://kubernetes.io/docs/tasks/tools/) and "+
				"make sure it's on the gateway's PATH",
			host.Name)
	}
	rt, err := t.newRuntime(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	target, err := t.resolveTarget(ctx, rt)
	if err != nil {
		_ = rt.cleanupCreatedPod(context.Background())
		rt.removeKubeconfig()
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	if err := rt.startPortForward(ctx, target, t.Port); err != nil {
		_ = rt.cleanupCreatedPod(context.Background())
		rt.removeKubeconfig()
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	rt.logger.Printf("kubernetes_port_forward/%s: forwarding %s/%s → %s",
		host.Name, rt.ns, target, rt.localAddr)
	return rt, nil
}

// newRuntime builds the request-time runtime struct shared by Open and
// ReconcileOrphans: it resolves the namespace default and, when the
// plugin owns its kubeconfig (Server set), mints the EKS bearer and
// writes a per-tunnel kubeconfig plus the reauth closure that re-mints
// it on demand. Callers that materialise a kubeconfig must call
// rt.removeKubeconfig() when done.
func (t *KubernetesPortForwardTunnel) newRuntime(ctx context.Context, host runtime.TunnelHost) (*kubernetesPortForwardTunnel, error) {
	logger := host.Logger
	if logger == nil {
		logger = log.Default()
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
	if t.Server != "" {
		path, reauth, err := t.writeKubeconfig(ctx, host)
		if err != nil {
			return nil, err
		}
		rt.kubeconfig = path
		rt.reauth = reauth
		// Context (kubeconfig context name) is meaningless once we own
		// the kubeconfig — clear it so kctlArgs doesn't double up with
		// a --context flag.
		rt.ctx = ""
	}
	return rt, nil
}

// writeKubeconfig materialises a self-contained kubeconfig (server +
// ca + bearer) backed by the bound credential. It returns the temp
// file path plus a reauth closure that re-mints a fresh bearer and
// rewrites the file in place.
//
// Why reauth exists: an EKS bearer embeds a presigned STS URL valid for
// only ~60 seconds (see eksPresignMiddleware's X-Amz-Expires=60).
// `kubectl port-forward` consumes the bearer once at handshake — within
// 60s of Open — and then holds the session, so the long-lived forward
// is fine with a single mint. But cleanupCreatedPod (and the startup
// reconcile sweep) make a *fresh* `kubectl delete` call long after Open,
// when the cached bearer has expired; without re-minting that delete
// 401s, the error is swallowed, and the pod leaks. reauth lets those
// late callers refresh the token before they shell out.
func (t *KubernetesPortForwardTunnel) writeKubeconfig(ctx context.Context, host runtime.TunnelHost) (string, func(context.Context) error, error) {
	if t.CACert == "" {
		return "", nil, errors.New("`server` set without `ca_cert`; inline the cluster CA (or `<<file:cluster-ca.pem>>`) so kubectl can verify the apiserver")
	}
	if host.Credential == nil {
		return "", nil, errors.New("`server` is set but no `credential` is bound; kubectl can't authenticate")
	}
	minter, ok := host.Credential.Body.(runtime.EKSBearerMinter)
	if !ok {
		return "", nil, fmt.Errorf("credential %q (%s) does not implement EKSBearerMinter — bind an `aws_credential`",
			host.Credential.Name, host.Credential.Type)
	}
	if t.ClusterName == "" || t.Region == "" {
		return "", nil, errors.New("`server` is set against an EKS-auth credential, so `cluster_name` + `region` are required")
	}
	dir := filepath.Join(host.StateDir, "tunnels", "kubernetes_port_forward")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, host.Name+"-kubeconfig-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("create kubeconfig temp: %w", err)
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("close kubeconfig: %w", err)
	}
	_ = os.Chmod(path, 0o600)

	credName := host.Credential.Name
	secrets := host.SecretStore
	reauth := func(ctx context.Context) error {
		// Re-fetch the secret each mint so credential rotation is
		// picked up without re-Opening the tunnel.
		sec, err := secrets.Get(credName)
		if err != nil {
			return fmt.Errorf("fetch credential secret %q: %w", credName, err)
		}
		bearer, err := minter.MintEKSBearer(ctx, sec, t.Region, t.ClusterName)
		if err != nil {
			return fmt.Errorf("mint EKS bearer: %w", err)
		}
		if err := os.WriteFile(path, []byte(buildEKSKubeconfig(t.Server, t.CACert, bearer)), 0o600); err != nil {
			return fmt.Errorf("write kubeconfig: %w", err)
		}
		return nil
	}
	if err := reauth(ctx); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return path, reauth, nil
}

// buildEKSKubeconfig produces a minimal v1 kubeconfig with cluster
// (server + inline CA) + user (static bearer) + matching context.
// Cleartext bearer in a 0600 temp file is fine because the gateway
// itself is the only consumer; nothing else on the host runs as the
// same uid by design.
func buildEKSKubeconfig(server, caPEM, bearer string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(caPEM))
	return strings.Join([]string{
		"apiVersion: v1",
		"kind: Config",
		"clusters:",
		"- name: cluster",
		"  cluster:",
		"    server: " + server,
		"    certificate-authority-data: " + enc,
		"users:",
		"- name: user",
		"  user:",
		"    token: " + bearer,
		"contexts:",
		"- name: ctx",
		"  context: { cluster: cluster, user: user }",
		"current-context: ctx",
		"",
	}, "\n")
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
		name, err := pickReadyPod(ctx, rt.kubeconfig, rt.ctx, rt.ns, t.Selector)
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
func pickReadyPod(ctx context.Context, kubeconfig, kctx, ns string, selector map[string]string) (string, error) {
	args := kctlArgs(kubeconfig, kctx, ns,
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

// kctlArgs prepends --kubeconfig / --context and --namespace flags
// (when set) to the given kubectl arg vector. When kubeconfig is set
// the plugin owns a per-tunnel config file, so --context isn't
// emitted (the file's current-context is correct by construction).
func kctlArgs(kubeconfig, kctx, ns string, args ...string) []string {
	out := []string{}
	if kubeconfig != "" {
		out = append(out, "--kubeconfig", kubeconfig)
	} else if kctx != "" {
		out = append(out, "--context", kctx)
	}
	if ns != "" {
		out = append(out, "-n", ns)
	}
	return append(out, args...)
}

// lookupKubectl reports whether `kubectl` is on PATH. A package var so
// tests can exercise the kubectl-driven paths without the binary
// installed.
var lookupKubectl = func() error {
	_, err := exec.LookPath("kubectl")
	return err
}

// runKubectl runs `kubectl ARGS...` and returns its stdout. Stderr
// is folded into the returned error on failure. It's a package var so
// tests can stub the kubectl boundary without a live cluster.
var runKubectl = func(ctx context.Context, args []string) (string, error) {
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

	ctx        string // kubectl --context (skipped when kubeconfig is set)
	kubeconfig string // kubectl --kubeconfig path, or "" to fall back to KUBECONFIG / ~/.kube/config
	ns         string

	// reauth re-mints the EKS bearer and rewrites the kubeconfig in
	// place. nil when the plugin uses an external kubeconfig (no Server
	// set) — there's no bearer to refresh. Late kubectl calls (pod
	// delete on Close, reconcile sweep) invoke it first because the
	// bearer minted at Open expires after ~60s.
	reauth func(context.Context) error

	// createdPod, if non-empty, is the name of a pod the plugin
	// applied at Open and should delete on Close (when cleanup=true).
	createdPod string
	cleanup    bool

	pf        *exec.Cmd
	localAddr string
	once      sync.Once
}

// removeKubeconfig deletes the temp kubeconfig the plugin minted at
// Open time, if any. No-op when the plugin used an external
// kubeconfig (KUBECONFIG / ~/.kube/config / explicit context).
func (t *kubernetesPortForwardTunnel) removeKubeconfig() {
	if t.kubeconfig == "" {
		return
	}
	path := t.kubeconfig
	t.kubeconfig = ""
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.logger.Printf("kubernetes_port_forward/%s: remove kubeconfig %s: %v", t.name, path, err)
	}
}

// applyAndWait shells out to `kubectl create -f -` + `kubectl wait
// --for=condition=Ready`. Returns the resolved pod name (which may
// differ from doc.name when `generateName` is used).
func (t *kubernetesPortForwardTunnel) applyAndWait(ctx context.Context, doc *podDoc) (string, error) {
	// Stamp the Clawpatrol-managed labels so the startup reconcile sweep
	// can find and delete pods orphaned by a previous daemon lifetime.
	raw, err := injectManagedLabels(doc.raw, t.name)
	if err != nil {
		return "", fmt.Errorf("label pod template: %w", err)
	}
	cmd := exec.CommandContext(ctx, "kubectl",
		kctlArgs(t.kubeconfig, t.ctx, t.ns, "create", "-f", "-", "-o", "name")...)
	cmd.Stdin = strings.NewReader(raw)
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

	waitArgs := kctlArgs(t.kubeconfig, t.ctx, t.ns,
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
	args := kctlArgs(t.kubeconfig, t.ctx, t.ns,
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
	var err error
	t.once.Do(func() {
		t.killPF()
		err = t.cleanupCreatedPod(context.Background())
		t.removeKubeconfig()
	})
	return err
}

// cleanupCreatedPod deletes the template-created pod, returning (not
// swallowing) any failure so the manager's CloseAll surfaces it. The
// createdPod name is cleared only on success: a failed delete keeps the
// name so the leak is observable in logs and the startup reconcile sweep
// (which matches on the managed labels) can mop it up next boot.
func (t *kubernetesPortForwardTunnel) cleanupCreatedPod(ctx context.Context) error {
	if t.createdPod == "" {
		return nil
	}
	name := t.createdPod
	t.logger.Printf("kubernetes_port_forward/%s: deleting pod %s/%s", t.name, t.ns, name)
	delCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Re-mint the bearer first: the kubeconfig written at Open carries a
	// ~60s presigned STS URL, long expired by the time a tunnel closes.
	// Without this the delete 401s and the pod leaks. Best-effort — an
	// external kubeconfig (no Server set) has no reauth and authenticates
	// on its own.
	if t.reauth != nil {
		if err := t.reauth(delCtx); err != nil {
			t.logger.Printf("kubernetes_port_forward/%s: re-mint bearer for pod delete failed: %v", t.name, err)
		}
	}
	args := kctlArgs(t.kubeconfig, t.ctx, t.ns, "delete", "pod/"+name, "--wait=false")
	if _, err := runKubectl(delCtx, args); err != nil {
		t.logger.Printf("kubernetes_port_forward/%s: delete pod %s/%s failed: %v", t.name, t.ns, name, err)
		return fmt.Errorf("delete pod %s/%s: %w", t.ns, name, err)
	}
	t.createdPod = ""
	return nil
}

// Managed-pod labels. The plugin stamps these on every
// template-created pod so a freshly-started gateway can find and delete
// pods orphaned by a previous lifetime (a SIGKILL / OOM / panic skips
// the SIGTERM-driven CloseAll, leaving the pod behind with no live
// owner). managedByLabelKey scopes the sweep to Clawpatrol; tunnelLabel
// scopes it to one tunnel so a sweep only ever touches pods its own
// config declares.
const (
	managedByLabelKey = "clawpatrol.dev/managed-by"
	managedByLabelVal = "clawpatrol"
	tunnelLabelKey    = "clawpatrol.dev/tunnel"
)

// managedBySelector renders the label selector matching pods this
// tunnel created.
func managedBySelector(tunnelName string) string {
	return managedByLabelKey + "=" + managedByLabelVal + "," + tunnelLabelKey + "=" + tunnelName
}

// injectManagedLabels round-trips the pod manifest through YAML to set
// metadata.labels[managed-by] + [tunnel] without disturbing the rest of
// the operator's template. Done programmatically (not by string
// splicing) so it survives any template shape — labels present or
// absent, metadata present or absent.
func injectManagedLabels(raw, tunnelName string) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return "", fmt.Errorf("decode pod yaml: %w", err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	meta, ok := doc["metadata"].(map[string]any)
	if !ok || meta == nil {
		meta = map[string]any{}
		doc["metadata"] = meta
	}
	labels, ok := meta["labels"].(map[string]any)
	if !ok || labels == nil {
		labels = map[string]any{}
		meta["labels"] = labels
	}
	labels[managedByLabelKey] = managedByLabelVal
	labels[tunnelLabelKey] = tunnelName
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("encode pod yaml: %w", err)
	}
	return string(out), nil
}

// ReconcileOrphans sweeps template-created pods left behind by a
// previous daemon lifetime. The host calls it once at startup (after
// config load) for every tunnel; it's a no-op for non-template modes
// and when cleanup is disabled. It lists pods carrying this tunnel's
// managed labels and deletes each one by name from that snapshot — safe
// to run concurrently with serving because a pod created after the list
// (a fresh generateName) can't appear in the snapshot, so a live
// forward is never torn out from under itself.
//
// Default-on: any template tunnel with cleanup != "keep" is swept. This
// catches both the daemon-crash case and any pods that leaked before
// this fix shipped.
func (t *KubernetesPortForwardTunnel) ReconcileOrphans(ctx context.Context, host runtime.TunnelHost) error {
	if t.Template == "" || t.Cleanup == "keep" {
		return nil
	}
	if err := lookupKubectl(); err != nil {
		// No kubectl means Open would fail too; stay quiet at startup.
		return nil
	}
	rt, err := t.newRuntime(ctx, host)
	if err != nil {
		return fmt.Errorf("kubernetes_port_forward/%s: reconcile: %w", host.Name, err)
	}
	defer rt.removeKubeconfig()

	sel := managedBySelector(host.Name)
	listArgs := kctlArgs(rt.kubeconfig, rt.ctx, rt.ns, "get", "pods", "-l", sel, "-o", "name")
	out, err := runKubectl(ctx, listArgs)
	if err != nil {
		return fmt.Errorf("kubernetes_port_forward/%s: list orphan pods (%s): %w", host.Name, sel, err)
	}
	names := strings.Fields(strings.TrimSpace(out))
	if len(names) == 0 {
		return nil
	}
	var firstErr error
	for _, raw := range names {
		name := strings.TrimPrefix(raw, "pod/")
		rt.logger.Printf("kubernetes_port_forward/%s: reconcile deleting orphan pod %s/%s", host.Name, rt.ns, name)
		delArgs := kctlArgs(rt.kubeconfig, rt.ctx, rt.ns, "delete", "pod/"+name, "--wait=false")
		if _, err := runKubectl(ctx, delArgs); err != nil {
			rt.logger.Printf("kubernetes_port_forward/%s: reconcile delete pod %s/%s failed: %v", host.Name, rt.ns, name, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("delete orphan pod %s/%s: %w", rt.ns, name, err)
			}
		}
	}
	return firstErr
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
			if t.Server != "" {
				b.SetAttributeValue("server", cty.StringVal(t.Server))
			}
			if t.CACert != "" {
				b.SetAttributeValue("ca_cert", cty.StringVal(t.CACert))
			}
			if t.ClusterName != "" {
				b.SetAttributeValue("cluster_name", cty.StringVal(t.ClusterName))
			}
			if t.Region != "" {
				b.SetAttributeValue("region", cty.StringVal(t.Region))
			}
			emitCommon(b, t.TunnelCommon())
		},
	})
}
