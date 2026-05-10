package tunnels

// kubernetes_port_forward tunnel: opens an SPDY port-forward to a
// pod (or service) in a Kubernetes cluster. Four mutually-exclusive
// target modes:
//
//   pod      = "<name>"             existing pod by name
//   service  = "<name>"             existing service by name (resolves
//                                   to a backend pod via the service's
//                                   selector + targetPort)
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
// The plugin ships no built-in pod manifests. `kubectl port-forward`
// only forwards to a port that is actively listening inside the pod,
// so a "default sleep pod" wouldn't actually serve traffic — if you
// want a jump pod, supply the manifest in `template`.
//
// Authentication: client-go's kubeconfig chain (KUBECONFIG, then
// ~/.kube/config). The `context` HCL field selects which named
// context to use; empty means kubeconfig's current-context. Falls
// back to in-cluster downward-API config when no kubeconfig is
// reachable, so the plugin works when the gateway itself runs as a
// pod.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// KubernetesPortForwardTunnel configures the tunnel runtime.
type KubernetesPortForwardTunnel struct {
	Context   string `hcl:"context,optional"`
	Namespace string `hcl:"namespace,optional"`

	// Exactly one of Pod / Service / Selector / Template must be set.
	Pod      string            `hcl:"pod,optional"`
	Service  string            `hcl:"service,optional"`
	Selector map[string]string `hcl:"selector,optional"`
	Template string            `hcl:"template,optional"`

	// Port is the pod-side port the forwarder targets. For service
	// mode it's the *service* port; the plugin resolves the matching
	// targetPort from spec.ports[*].port == this value.
	Port int `hcl:"port"`

	// Cleanup is meaningful only in template mode — controls whether
	// the pod the plugin applied at Open is deleted on tunnel
	// teardown. "delete" (default) is right for the common create-on-
	// demand case; "keep" disables deletion.
	Cleanup string `hcl:"cleanup,optional"`

	// Framework-level common attrs.
	Share      string `hcl:"share,optional"`
	Keepalive  string `hcl:"keepalive,optional"`
	Via        string `hcl:"via,optional"`
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

// Open builds the kubeconfig-derived REST client, resolves (or
// creates) the target pod, and starts a port-forward. Returns a
// Tunnel whose Dial connects to the local listener client-go
// stands up.
func (t *KubernetesPortForwardTunnel) Open(ctx context.Context, host runtime.TunnelHost, _ runtime.Tunnel) (runtime.Tunnel, error) {
	logger := host.Logger
	if logger == nil {
		logger = log.Default()
	}
	if err := t.validateModes(); err != nil {
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}
	cfg, err := buildKubeConfig(t.Context)
	if err != nil {
		return nil, fmt.Errorf("kubernetes_port_forward/%s: kubeconfig: %w", host.Name, err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes_port_forward/%s: clientset: %w", host.Name, err)
	}
	ns := t.Namespace
	if ns == "" {
		ns = "default"
	}

	rt := &kubernetesPortForwardTunnel{
		name:      host.Name,
		logger:    logger,
		ready:     make(chan struct{}),
		stop:      make(chan struct{}),
		clientset: clientset,
		ns:        ns,
	}

	pod, port, err := t.resolveTarget(ctx, clientset, ns, host.Name, rt)
	if err != nil {
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}

	if err := rt.startPortForward(ctx, cfg, clientset, ns, pod, port); err != nil {
		// Clean up created pod on failure so we don't leak.
		rt.cleanupCreatedPod(context.Background())
		return nil, fmt.Errorf("kubernetes_port_forward/%s: %w", host.Name, err)
	}

	logger.Printf("kubernetes_port_forward/%s: forwarding %s/%s:%d → %s", host.Name, ns, pod, port, rt.localAddr)
	return rt, nil
}

// validateModes enforces exactly-one-of pod / service / selector /
// template.
func (t *KubernetesPortForwardTunnel) validateModes() error {
	modes := 0
	for _, set := range []bool{t.Pod != "", t.Service != "", len(t.Selector) > 0, t.Template != ""} {
		if set {
			modes++
		}
	}
	if modes == 0 {
		return errors.New("set exactly one of `pod`, `service`, `selector`, `template`")
	}
	if modes > 1 {
		return errors.New("set exactly one of `pod`, `service`, `selector`, `template`")
	}
	if t.Port == 0 {
		return errors.New("`port` is required (pod-side port; for service mode, the service port)")
	}
	return nil
}

// resolveTarget returns (pod-name, pod-side-port). For pod mode the
// caller-supplied Port is the pod-side port. For service mode we
// look up the service, find spec.ports[port=t.Port], and return its
// resolved targetPort + a backend pod from the selector. For
// selector mode we just pick the first ready pod with t.Port. For
// template mode we apply the manifest, wait for ready, return its
// name + t.Port.
func (t *KubernetesPortForwardTunnel) resolveTarget(ctx context.Context, cs kubernetes.Interface, ns, tunnelName string, rt *kubernetesPortForwardTunnel) (string, int, error) {
	switch {
	case t.Pod != "":
		p, err := cs.CoreV1().Pods(ns).Get(ctx, t.Pod, metav1.GetOptions{})
		if err != nil {
			return "", 0, fmt.Errorf("get pod %s/%s: %w", ns, t.Pod, err)
		}
		if !podReady(p) {
			return "", 0, fmt.Errorf("pod %s/%s is not ready", ns, t.Pod)
		}
		return p.Name, t.Port, nil

	case t.Service != "":
		svc, err := cs.CoreV1().Services(ns).Get(ctx, t.Service, metav1.GetOptions{})
		if err != nil {
			return "", 0, fmt.Errorf("get service %s/%s: %w", ns, t.Service, err)
		}
		if len(svc.Spec.Selector) == 0 {
			return "", 0, fmt.Errorf("service %s/%s has no selector — port-forward needs to resolve to a backend pod", ns, t.Service)
		}
		var matchedPort *corev1.ServicePort
		for i, p := range svc.Spec.Ports {
			if int(p.Port) == t.Port {
				matchedPort = &svc.Spec.Ports[i]
				break
			}
		}
		if matchedPort == nil {
			return "", 0, fmt.Errorf("service %s/%s has no port %d (declared ports: %v)", ns, t.Service, t.Port, svcPortNumbers(svc))
		}
		pod, err := pickReadyPod(ctx, cs, ns, svc.Spec.Selector)
		if err != nil {
			return "", 0, fmt.Errorf("service %s/%s: %w", ns, t.Service, err)
		}
		// Resolve targetPort: numeric → use it; named → look up
		// the matching containerPort name on the chosen pod.
		targetPort, err := resolveTargetPort(pod, matchedPort.TargetPort)
		if err != nil {
			return "", 0, fmt.Errorf("service %s/%s: %w", ns, t.Service, err)
		}
		return pod.Name, targetPort, nil

	case len(t.Selector) > 0:
		pod, err := pickReadyPod(ctx, cs, ns, t.Selector)
		if err != nil {
			return "", 0, err
		}
		return pod.Name, t.Port, nil

	case t.Template != "":
		pod, err := podFromTemplate(t.Template)
		if err != nil {
			return "", 0, fmt.Errorf("template: %w", err)
		}
		name, err := t.applyAndWait(ctx, cs, ns, tunnelName, rt, pod)
		return name, t.Port, err
	}
	return "", 0, errors.New("no target mode set (validateModes should have caught this)")
}

// pickReadyPod lists pods matching selector and returns the first
// one in Running + Ready state.
func pickReadyPod(ctx context.Context, cs kubernetes.Interface, ns string, selector map[string]string) (*corev1.Pod, error) {
	sel := labelSelector(selector)
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("list pods %s by %q: %w", ns, sel, err)
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if podReady(p) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no ready pods match selector %q in namespace %q", sel, ns)
}

// resolveTargetPort turns a Service.spec.ports[*].targetPort
// (IntOrString) into a numeric pod-side port. Numeric values are
// returned as-is; named values are matched against the chosen pod's
// container ports.
func resolveTargetPort(pod *corev1.Pod, target intstr.IntOrString) (int, error) {
	if target.Type == intstr.Int {
		return int(target.IntVal), nil
	}
	for _, c := range pod.Spec.Containers {
		for _, p := range c.Ports {
			if p.Name == target.StrVal {
				return int(p.ContainerPort), nil
			}
		}
	}
	return 0, fmt.Errorf("named targetPort %q not found on pod %s", target.StrVal, pod.Name)
}

// applyAndWait creates pod in ns and polls until it reaches
// Running + Ready or the context expires. Records the created
// name on rt so Close cleans it up (unless cleanup = "keep").
func (t *KubernetesPortForwardTunnel) applyAndWait(ctx context.Context, cs kubernetes.Interface, ns, tunnelName string, rt *kubernetesPortForwardTunnel, pod *corev1.Pod) (string, error) {
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[managedByLabel] = tunnelName
	created, err := cs.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create pod: %w", err)
	}
	if t.Cleanup != "keep" {
		rt.createdPod = created.Name
	}
	rt.logger.Printf("kubernetes_port_forward/%s: created pod %s/%s", tunnelName, ns, created.Name)

	deadline := time.Now().Add(2 * time.Minute)
	for {
		p, err := cs.CoreV1().Pods(ns).Get(ctx, created.Name, metav1.GetOptions{})
		if err == nil && podReady(p) {
			return created.Name, nil
		}
		if time.Now().After(deadline) {
			return created.Name, fmt.Errorf("pod %s/%s never became ready (2m)", ns, created.Name)
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return created.Name, ctx.Err()
		}
	}
}

const managedByLabel = "clawpatrol.io/tunnel"

// podFromTemplate decodes a YAML manifest into a corev1.Pod.
// Single-document only; non-Pod kinds are rejected so the cleanup
// path stays simple. Operators with more elaborate shapes (Deployment
// + Service, etc.) can manage them externally and use `pod`,
// `service`, or `selector`.
func podFromTemplate(yaml string) (*corev1.Pod, error) {
	var pod corev1.Pod
	if err := sigsyaml.Unmarshal([]byte(yaml), &pod); err != nil {
		return nil, fmt.Errorf("decode pod yaml: %w", err)
	}
	if pod.Kind != "" && pod.Kind != "Pod" {
		return nil, fmt.Errorf("template kind %q not supported (Pod only)", pod.Kind)
	}
	if pod.Name == "" && pod.GenerateName == "" {
		return nil, fmt.Errorf("template must set metadata.name or metadata.generateName")
	}
	return &pod, nil
}

// labelSelector renders {key: val} as a comma-joined key=val list.
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

// svcPortNumbers extracts the numeric port column from a Service
// for the "no port N declared" diagnostic.
func svcPortNumbers(svc *corev1.Service) []int32 {
	out := make([]int32, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		out = append(out, p.Port)
	}
	return out
}

func podReady(p *corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// buildKubeConfig loads kubeconfig from the standard chain, then
// (when contextName is set) overrides the current-context. Falls
// back to in-cluster config when no kubeconfig is reachable.
func buildKubeConfig(contextName string) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	cfg, err := cc.ClientConfig()
	if err == nil {
		return cfg, nil
	}
	if inCluster, icErr := rest.InClusterConfig(); icErr == nil {
		return inCluster, nil
	}
	return nil, err
}

type kubernetesPortForwardTunnel struct {
	name   string
	logger *log.Logger

	clientset kubernetes.Interface
	ns        string
	// createdPod, if non-empty, is the name of a pod the plugin
	// applied at Open and should delete on Close.
	createdPod string

	pf        *portforward.PortForwarder
	localAddr string
	ready     chan struct{}
	stop      chan struct{}
	once      sync.Once
}

// startPortForward boots the port-forward in a background goroutine
// and blocks until the SPDY stream signals ready.
func (t *kubernetesPortForwardTunnel) startPortForward(ctx context.Context, cfg *rest.Config, cs kubernetes.Interface, ns, pod string, port int) error {
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return fmt.Errorf("spdy roundtripper: %w", err)
	}
	req := cs.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(ns).
		Name(pod).
		SubResource("portforward")
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL())

	ports := []string{fmt.Sprintf("0:%d", port)} // 0 = ephemeral local
	addrs := []string{"127.0.0.1"}

	pf, err := portforward.NewOnAddresses(dialer, addrs, ports, t.stop, t.ready, io.Discard, io.Discard)
	if err != nil {
		return fmt.Errorf("portforward init: %w", err)
	}
	t.pf = pf
	go func() {
		if err := pf.ForwardPorts(); err != nil {
			t.logger.Printf("kubernetes_port_forward/%s: forward exited: %v", t.name, err)
		}
	}()

	select {
	case <-t.ready:
	case <-ctx.Done():
		close(t.stop)
		return ctx.Err()
	case <-time.After(30 * time.Second):
		close(t.stop)
		return fmt.Errorf("port-forward never became ready (30s)")
	}

	bound, err := pf.GetPorts()
	if err != nil {
		return fmt.Errorf("get bound ports: %w", err)
	}
	if len(bound) == 0 {
		return fmt.Errorf("no bound ports after ready")
	}
	t.localAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(bound[0].Local)))
	return nil
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
		close(t.stop)
		t.cleanupCreatedPod(context.Background())
	})
	return nil
}

func (t *kubernetesPortForwardTunnel) cleanupCreatedPod(ctx context.Context) {
	if t.createdPod == "" || t.clientset == nil {
		return
	}
	name := t.createdPod
	t.createdPod = ""
	t.logger.Printf("kubernetes_port_forward/%s: deleting pod %s/%s", t.name, t.ns, name)
	delCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := t.clientset.CoreV1().Pods(t.ns).Delete(delCtx, name, metav1.DeleteOptions{}); err != nil {
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
