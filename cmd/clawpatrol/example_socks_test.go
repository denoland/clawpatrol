package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestExampleSocksTunnel dials an HTTP target through the example plugin's
// example_socks tunnel: gateway -> example_socks.Dial -> brokered
// DialUpstream(tcp, proxy) -> in-test SOCKS5 server -> CONNECT -> target.
// Self-contained (no external proxy/server), so it runs in CI and proves
// the example tunnel actually works through the brokered transport dial.
func TestExampleSocksTunnel(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-through-example-socks")
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	socksAddr := startTestSocks5(t)

	pluginPath := buildSharedExamplePlugin(t)
	mgr := sharedExampleManager() // carries a transport dialer for the tunnel
	config.SetPluginLoader(mgr)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	gw, diags := config.LoadBytes([]byte(fmt.Sprintf(`
plugin "example" {
  source  = %q
  network = "none"
}
gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
tunnel "example_socks" "proxy1" {
  proxy = %q
}
endpoint "example_https" "demo" {
  hosts    = ["demo.invalid"]
  upstream = "http://127.0.0.1:8000"
}
profile "default" { credentials = [] }
`, pluginPath, socksAddr)), "example-socks.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ct := policy.Tunnels["proxy1"]
	if ct == nil {
		t.Fatal("no compiled tunnel 'proxy1'")
	}

	tm := NewTunnelManager(runtime.EnvSecretStore{}, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tun, release, err := tm.Acquire(ctx, ct, "demo")
	if err != nil {
		t.Fatalf("acquire example_socks: %v", err)
	}
	defer release()

	conn, err := tun.Dial(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", targetAddr); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "hello-through-example-socks") {
		t.Fatalf("got status %d body %q", resp.StatusCode, body)
	}
}

// startTestSocks5 starts a minimal SOCKS5 CONNECT proxy on 127.0.0.1 and
// returns its address.
func startTestSocks5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go testSocksConnect(c)
		}
	}()
	return ln.Addr().String()
}

func testSocksConnect(c net.Conn) {
	defer func() { _ = c.Close() }()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	_, _ = c.Write([]byte{0x05, 0x00})
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		b := make([]byte, int(l[0]))
		_, _ = io.ReadFull(c, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		_, _ = io.ReadFull(c, b)
		host = net.IP(b).String()
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))))
	if err != nil {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = up.Close() }()
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}
