package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/denoland/clawpatrol/internal/sandbox/sandboxtest"
)

// buildSharedExamplePlugin compiles pluginsdk/example once into a
// process-stable location. The shared manager spawns it only on the
// first load (it dedups by plugin name), so the binary must outlive
// any single test's t.TempDir().
var buildSharedExamplePlugin = func() func(t *testing.T) string {
	var (
		once sync.Once
		path string
		err  error
	)
	return func(t *testing.T) string {
		t.Helper()
		once.Do(func() {
			moduleRoot := moduleRootForTest(t)
			dir, derr := os.MkdirTemp("", "cp-example-plugin-")
			if derr != nil {
				err = derr
				return
			}
			path = filepath.Join(dir, "example")
			cmd := exec.Command("go", "build", "-o", path, "./pluginsdk/example")
			cmd.Dir = moduleRoot
			if b, berr := cmd.CombinedOutput(); berr != nil {
				err = fmt.Errorf("build example plugin: %w\n%s", berr, b)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
}()

// sharedExampleManager keeps one example-plugin subprocess +
// registration alive for the whole package. The plugin registers
// fixed-name types and facets in the process-global registry, which
// has no deregistration, so loading it twice in one test binary would
// collide. The manager dedups by plugin name, so reusing it across
// loads re-registers nothing.
var sharedExampleManager = sync.OnceValue(func() *extplugin.Manager {
	m := extplugin.New(nil)
	// A tunnel plugin (e.g. example_socks) opens its transport through the
	// gateway's brokered dial; with no `via` the gateway dials directly.
	// Wire it here, before any test spawns the plugin, so the dialer is
	// captured at spawn regardless of test order. Inert for endpoint tests.
	m.SetTransportDialer(func(network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	})
	return m
})

// loadDemoPluginPolicy loads a config wired to the real example plugin
// (network = "none": the https endpoint must work through the
// brokered dial alone) and compiles it.
func loadDemoPluginPolicy(t *testing.T, dialList string) *config.CompiledPolicy {
	t.Helper()
	pluginPath := buildSharedExamplePlugin(t)

	mgr := sharedExampleManager()
	config.SetPluginLoader(mgr)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	gw, diags := config.LoadBytes([]byte(fmt.Sprintf(`
// network = "none": the example plugin reaches the network only through
// the gateway's brokered dial, so this exercises that path with no
// plugin-side network.
plugin "example" {
  source  = %q
  network = "none"
}

gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "example_https" "demo-site" {
  hosts    = ["demo.invalid"]
  upstream = "http://127.0.0.1:8000"
  %s
}
credential "example_magic_token" "demo" {
  endpoints   = [example_https.demo-site]
  header_name = "X-Magic"
}
profile "default" { credentials = [example_magic_token.demo] }
rule "allow-get" {
  endpoint  = example_https.demo-site
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
`, pluginPath, dialList)), "extplugin-dial-e2e.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return policy
}

type dialE2EHarness struct {
	upstreamAddr string
	upstreamHdr  chan string

	eventsMu sync.Mutex
	events   []runtime.ConnEvent

	dialedMu sync.Mutex
	dialed   []string
}

func (h *dialE2EHarness) eventsSnapshot() []runtime.ConnEvent {
	h.eventsMu.Lock()
	defer h.eventsMu.Unlock()
	return append([]runtime.ConnEvent(nil), h.events...)
}

// demoResp is the read-and-closed result of one brokered-dial
// request, so the helper doesn't leak an open *http.Response.
type demoResp struct {
	StatusCode int
	Body       []byte
}

// runDemoHTTPSRequest drives one HTTPS request from a fake agent
// through the real example plugin's HandleConn and returns the
// response (nil when the conn died before a response).
func runDemoHTTPSRequest(t *testing.T, policy *config.CompiledPolicy, h *dialE2EHarness) *demoResp {
	t.Helper()
	ep := policy.Endpoints["demo-site"]
	if ep == nil {
		t.Fatal("missing demo-site endpoint")
	}
	connRT, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime)
	if !ok {
		t.Fatalf("endpoint runtime %T is not a ConnEndpointRuntime", ep.Plugin.Runtime)
	}
	certs, _ := inMemoryCertCache(t)

	// The config says upstream 127.0.0.1:8000; rewrite to the real
	// httptest port at the dial layer so the plugin's brokered
	// target matches the configured allow-list entry.
	serverConn, clientConn := net.Pipe()
	ch := &runtime.ConnHandle{
		Conn:         serverConn,
		Endpoint:     ep,
		Policy:       policy,
		Profile:      "default",
		PeerIP:       "10.55.0.2",
		Secrets:      externalHTTPTestSecretStore{"demo": "magic-secret"},
		DstPort:      443,
		UpstreamHost: "demo.invalid",
		MintCert: func(host string) (*tls.Certificate, error) {
			return certs.mint(host)
		},
		DialUpstream: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h.dialedMu.Lock()
			h.dialed = append(h.dialed, addr)
			h.dialedMu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, h.upstreamAddr)
		},
		Emit: func(ev runtime.ConnEvent) {
			h.eventsMu.Lock()
			h.events = append(h.events, ev)
			h.eventsMu.Unlock()
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = connRT.HandleConn(context.Background(), ch)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "demo.invalid"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://demo.invalid/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	waitDone := func() {
		_ = clientTLS.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("plugin HandleConn did not exit")
		}
	}
	// Localize a hang (plugin never responds) to this test instead of
	// the whole-binary timeout.
	_ = clientTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		waitDone()
		return nil
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		waitDone()
		t.Fatalf("read body: %v", readErr)
	}
	out := &demoResp{StatusCode: resp.StatusCode, Body: body}
	waitDone()
	return out
}

func newDialE2EHarness(t *testing.T) *dialE2EHarness {
	t.Helper()
	h := &dialE2EHarness{upstreamHdr: make(chan string, 1)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case h.upstreamHdr <- r.Header.Get("X-Magic"):
		default:
		}
		_, _ = fmt.Fprint(w, "upstream says hi")
	}))
	t.Cleanup(upstream.Close)
	h.upstreamAddr = upstream.Listener.Addr().String()
	return h
}

// TestExampleHTTPSEndpointThroughBrokeredDial proves the demo HTTPS
// endpoint plugin works with zero plugin-side network access: the
// upstream connection is opened by the gateway on the plugin's
// behalf, the magic header lands upstream, and the mutated body
// comes back to the agent. The plugin subprocess runs under the
// enforced sandbox with network = "none".
func TestExampleHTTPSEndpointThroughBrokeredDial(t *testing.T) {
	sandboxtest.RequireBackend(t)
	h := newDialE2EHarness(t)
	policy := loadDemoPluginPolicy(t, `dial = ["127.0.0.1:8000"]`)

	resp := runDemoHTTPSRequest(t, policy, h)
	if resp == nil {
		t.Fatal("no response from plugin")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "upstream says hi") || !strings.Contains(string(resp.Body), "bye!") {
		t.Fatalf("body = %q, want upstream content with bye! suffix", resp.Body)
	}

	select {
	case got := <-h.upstreamHdr:
		if got != "magic-secret" {
			t.Fatalf("upstream X-Magic = %q, want injected secret", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream saw no request")
	}

	h.dialedMu.Lock()
	dialed := append([]string(nil), h.dialed...)
	h.dialedMu.Unlock()
	if len(dialed) != 1 || dialed[0] != "127.0.0.1:8000" {
		t.Fatalf("gateway dialed %v, want the allow-listed target once", dialed)
	}

	var sawAllowDial bool
	for _, ev := range h.eventsSnapshot() {
		if ev.Verb == "dial" && ev.Action == "allow" {
			sawAllowDial = true
		}
	}
	if !sawAllowDial {
		t.Fatal("no allow audit event for the brokered dial")
	}
}

// TestBrokeredDialRefusesUnsanctionedTarget removes the dial
// allow-list entry: the plugin's upstream target is no longer
// sanctioned, the gateway must refuse the dial (never invoking the
// host dialer) and audit the refusal.
func TestBrokeredDialRefusesUnsanctionedTarget(t *testing.T) {
	sandboxtest.RequireBackend(t)
	h := newDialE2EHarness(t)
	policy := loadDemoPluginPolicy(t, "")

	resp := runDemoHTTPSRequest(t, policy, h)
	if resp != nil {
		t.Fatalf("got status %d, want connection failure", resp.StatusCode)
	}

	h.dialedMu.Lock()
	dialed := append([]string(nil), h.dialed...)
	h.dialedMu.Unlock()
	if len(dialed) != 0 {
		t.Fatalf("gateway dialer invoked for refused target: %v", dialed)
	}

	var sawDenyDial bool
	for _, ev := range h.eventsSnapshot() {
		if ev.Verb == "dial" && ev.Action == "deny" {
			sawDenyDial = true
			if !strings.Contains(ev.Summary, "127.0.0.1:8000") {
				t.Errorf("deny event summary %q does not name the target", ev.Summary)
			}
		}
	}
	if !sawDenyDial {
		t.Fatal("no deny audit event for the refused dial")
	}
}
