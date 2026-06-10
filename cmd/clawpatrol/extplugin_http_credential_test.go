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
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all" // register built-in plugins
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type externalHTTPTestSecretStore map[string]string

func (s externalHTTPTestSecretStore) Get(name string) (runtime.Secret, error) {
	v, ok := s[name]
	if !ok {
		return runtime.Secret{}, fmt.Errorf("unexpected secret lookup %q", name)
	}
	return runtime.Secret{Bytes: []byte(v)}, nil
}

func TestExternalCredentialInjectsAuthorizationThroughBuiltInHTTPS(t *testing.T) {
	typeName := fmt.Sprintf("ext_https_cred_%d", time.Now().UnixNano())
	pluginPath := buildExternalHTTPTestPlugin(t, typeName)

	mgr := extplugin.New(nil)
	config.SetPluginLoader(mgr)
	t.Cleanup(func() {
		mgr.Stop()
		config.SetPluginLoader(nil)
	})

	gw, diags := config.LoadBytes([]byte(fmt.Sprintf(`
plugin "extcredtest" { source = %q }

gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential %q "external" {
  endpoint    = https.api
  placeholder = "PH_external"
}
profile "default" { credentials = [%s.external] }
rule "allow-api" {
  endpoint = https.api
  verdict  = "allow"
}
`, pluginPath, typeName, typeName)), "external-http-credential-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := policy.Endpoints["api"]
	if ep == nil {
		t.Fatalf("missing api endpoint")
	}
	if _, ok := policy.Credentials["external"].Body.(runtime.HTTPCredentialRuntime); !ok {
		t.Fatalf("external credential body does not implement HTTPCredentialRuntime")
	}

	upstreamAuth := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()

	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(sink.ch)
	events, cancelEvents := sink.Subscribe()
	defer cancelEvents()
	certs, _ := inMemoryCertCache(t)
	g := &Gateway{certs: certs, sink: sink, secrets: externalHTTPTestSecretStore{"external": "real-external-token"}}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, tr)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.mitmHTTPS(serverConn, "api.example.test", ep)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.example.test"})
	defer func() { _ = clientTLS.Close() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.example.test/v1/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer PH_external")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case got := <-upstreamAuth:
		if got != "Bearer real-external-token" {
			t.Fatalf("upstream Authorization = %q, want real token", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream request")
	}

	var end Event
	select {
	case end = <-endEvent(events):
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for terminal audit event")
	}
	if strings.Contains(fmt.Sprint(end.ReqHeaders), "real-external-token") {
		t.Fatalf("request headers audit leaked injected external credential: %#v", end.ReqHeaders)
	}
	if got := end.ReqHeaders["X-Magic"]; got != credentialSampleRedaction {
		t.Fatalf("X-Magic audit header = %q, want credential redaction marker", got)
	}

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
}

func TestExternalCredentialPlaceholderDispatchThroughBuiltInHTTPS(t *testing.T) {
	typeName := fmt.Sprintf("ext_https_cred_%d", time.Now().UnixNano())
	pluginPath := buildExternalHTTPTestPlugin(t, typeName)

	mgr := extplugin.New(nil)
	config.SetPluginLoader(mgr)
	t.Cleanup(func() {
		mgr.Stop()
		config.SetPluginLoader(nil)
	})

	gw, diags := config.LoadBytes([]byte(fmt.Sprintf(`
plugin "extcredtest" { source = %q }

gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential %q "one" {
  endpoint    = https.api
  placeholder = "PH_one"
}
credential %q "two" {
  endpoint    = https.api
  placeholder = "PH_two"
}
profile "default" { credentials = [%s.one, %s.two] }
rule "allow-api" {
  endpoint = https.api
  verdict  = "allow"
}
`, pluginPath, typeName, typeName, typeName, typeName)), "external-http-placeholder-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := policy.Endpoints["api"]

	upstreamAuth := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()

	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(sink.ch)
	certs, _ := inMemoryCertCache(t)
	g := &Gateway{certs: certs, sink: sink, secrets: externalHTTPTestSecretStore{
		"one": "real-token-one",
		"two": "real-token-two",
	}}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, tr)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.mitmHTTPS(serverConn, "api.example.test", ep)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.example.test"})
	defer func() { _ = clientTLS.Close() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.example.test/v1/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer PH_two")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case got := <-upstreamAuth:
		if got != "Bearer real-token-two" {
			t.Fatalf("upstream Authorization = %q, want second credential token", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream request")
	}

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
}

func buildExternalHTTPTestPlugin(t *testing.T, typeName string) string {
	t.Helper()
	dir := t.TempDir()
	moduleRoot := moduleRootForTest(t)
	goMod := fmt.Sprintf(`module extcredtest

go 1.26.3

require github.com/denoland/clawpatrol v0.0.0

replace github.com/denoland/clawpatrol => %s
`, moduleRoot)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	rootSum, err := os.ReadFile(filepath.Join(moduleRoot, "go.sum"))
	if err != nil {
		t.Fatalf("read root go.sum: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), rootSum, 0644); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	mainGo := fmt.Sprintf(`package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/denoland/clawpatrol/pluginsdk"
)

func main() {
	pluginsdk.Run(&pluginsdk.Plugin{
		Name: "extcredtest",
		Credentials: []pluginsdk.CredentialDef{{
			TypeName: %q,
			Disambiguators: []string{"placeholder"},
			HTTPInject: true,
			Build: func(req pluginsdk.BuildRequest) (any, error) {
				return pluginsdk.CredentialBuildResult{
					Canonical: map[string]string{"instance": req.InstanceName},
					Metadata: pluginsdk.CredentialMetadata{
						SecretSlots: []pluginsdk.SecretSlot{{Label: "External token"}},
						EnvVars: []pluginsdk.EnvVar{{Name: "EXTERNAL_TOKEN", Value: "PH_external", Description: "placeholder"}},
						HTTPInject: true,
					},
				}, nil
			},
			InjectHTTP: func(_ context.Context, req pluginsdk.HTTPInjectRequest) (*pluginsdk.HTTPInjectResponse, error) {
				if len(req.CredentialSecret) == 0 {
					return nil, fmt.Errorf("empty credential secret")
				}
				if len(req.CredentialCanonicalConfig) == 0 {
					return nil, fmt.Errorf("empty canonical config")
				}
				if got := req.Headers.Get("Authorization"); !strings.HasPrefix(got, "Bearer PH_") {
					return nil, fmt.Errorf("authorization = %%q", got)
				}
				return &pluginsdk.HTTPInjectResponse{
					Headers: []pluginsdk.HeaderMutation{
						{Op: pluginsdk.HeaderSet, Name: "Authorization", Values: []string{"Bearer " + string(req.CredentialSecret)}},
						{Op: pluginsdk.HeaderSet, Name: "X-Magic", Values: []string{string(req.CredentialSecret)}},
					},
					Redactions: []string{string(req.CredentialSecret)},
				}, nil
			},
		}},
	})
}
`, typeName)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	bin := filepath.Join(dir, "extcredtest")
	cmd := exec.Command("go", "build", "-mod=mod", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build external test plugin: %v\n%s", err, string(out))
	}
	return bin
}

func moduleRootForTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return filepath.ToSlash(wd)
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			t.Fatalf("could not find module root")
		}
		wd = parent
	}
}
