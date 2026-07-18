package main

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const unknownHostSNI = "unmatched.example.test"

type sniDispatchDialer struct {
	calls     atomic.Int32
	addresses chan string
	upstreams chan net.Conn
}

func newSNIDispatchDialer() *sniDispatchDialer {
	return &sniDispatchDialer{
		addresses: make(chan string, 4),
		upstreams: make(chan net.Conn, 4),
	}
}

func (d *sniDispatchDialer) Dial(_ string, address string) (net.Conn, error) {
	spliceConn, observeConn := net.Pipe()
	d.calls.Add(1)
	d.addresses <- address
	d.upstreams <- observeConn
	return spliceConn, nil
}

func (d *sniDispatchDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return d.Dial(network, address)
	}
}

func TestSNIDispatchUnknownHostPolicy(t *testing.T) {
	tests := []struct {
		name      string
		hcl       string
		wantRelay bool
	}{
		{
			name: "deny",
			hcl: `
defaults { unknown_host = "deny" }
profile "default" { credentials = [] }
`,
		},
		{
			name: "explicit passthrough",
			hcl: `
defaults { unknown_host = "passthrough" }
profile "default" { credentials = [] }
`,
			wantRelay: true,
		},
		{
			name: "defaults block absent",
			hcl: `
profile "default" { credentials = [] }
`,
			wantRelay: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gatewayWithPolicy(t, tt.hcl)
			g.onboard = newOnboardRegistry()
			sink, err := NewSink(nil, 1)
			if err != nil {
				t.Fatalf("NewSink: %v", err)
			}
			g.sink = sink
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := sink.Close(ctx); err != nil {
					t.Errorf("close sink: %v", err)
				}
			})

			dialer := newSNIDispatchDialer()
			g.dialer = dialer
			serverConn, clientConn := net.Pipe()
			g.onboard.profileByIP[peerIP(serverConn)] = "default"
			t.Cleanup(func() { _ = clientConn.Close() })

			handlerDone := make(chan struct{})
			go func() {
				g.handle(serverConn, "", 443)
				close(handlerDone)
			}()

			if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("set client deadline: %v", err)
			}
			handshakeDone := make(chan error, 1)
			go func() {
				tlsClient := tls.Client(clientConn, &tls.Config{
					ServerName:         unknownHostSNI,
					InsecureSkipVerify: true, // The test observes dispatch, not a completed TLS session.
				})
				handshakeDone <- tlsClient.Handshake()
			}()

			if tt.wantRelay {
				var upstream net.Conn
				select {
				case upstream = <-dialer.upstreams:
				case <-time.After(2 * time.Second):
					t.Fatal("gateway did not dial passthrough upstream")
				}
				if err := upstream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatalf("set upstream deadline: %v", err)
				}
				host, _, err := peekSNI(upstream)
				if err != nil {
					_ = upstream.Close()
					t.Fatalf("read relayed ClientHello: %v", err)
				}
				if host != unknownHostSNI {
					_ = upstream.Close()
					t.Errorf("relayed SNI = %q, want %q", host, unknownHostSNI)
				}
				_ = upstream.Close()
				_ = clientConn.Close()

				select {
				case address := <-dialer.addresses:
					if want := net.JoinHostPort(unknownHostSNI, "443"); address != want {
						t.Errorf("dial address = %q, want %q", address, want)
					}
				default:
					t.Error("missing dial address")
				}
			} else {
				select {
				case upstream := <-dialer.upstreams:
					_ = upstream.Close()
					t.Error("deny policy dialed an upstream")
				case <-handlerDone:
				}
			}

			select {
			case <-handlerDone:
			case <-time.After(2 * time.Second):
				t.Fatal("gateway handler did not return")
			}
			select {
			case err := <-handshakeDone:
				if err == nil {
					t.Fatal("TLS handshake unexpectedly succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("TLS client handshake did not return")
			}

			wantDials := int32(0)
			if tt.wantRelay {
				wantDials = 1
			}
			if got := dialer.calls.Load(); got != wantDials {
				t.Errorf("upstream dial count = %d, want %d", got, wantDials)
			}
		})
	}
}

// TestSNIDispatchMarkerExcludesBuiltinConnEndpoints guards the :443 SNI
// dispatch branch in g.handle. That branch hands a connection to an
// endpoint plugin that terminates TLS itself. Built-in wire-protocol conn
// endpoints (postgres / clickhouse_native / ssh) also satisfy
// runtime.ConnEndpointRuntime, but they can't read a raw TLS ClientHello —
// they route via VIP / direct-IP, not SNI-on-443. So their compiled body
// must NOT satisfy the TLSTerminates() marker the branch gates on;
// otherwise a postgres endpoint declared with a bare/wildcard host and hit
// on :443 would be misrouted to the plugin path and break.
func TestSNIDispatchMarkerExcludesBuiltinConnEndpoints(t *testing.T) {
	g := gatewayWithPolicy(t, `
endpoint "postgres" "pg" { host = "pg.example.com:5432" }
credential "postgres_credential" "pg-user" { endpoint = postgres.pg }
profile "default" { credentials = [postgres_credential.pg-user] }
`)
	ep := g.Policy().Endpoints["pg"]
	if ep == nil {
		t.Fatal("missing pg endpoint")
	}
	// Premise: postgres is a conn runtime, so the broader
	// ConnEndpointRuntime check alone would have misrouted it.
	if _, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime); !ok {
		t.Fatal("expected built-in postgres to be a ConnEndpointRuntime")
	}
	if tt, ok := ep.Body.(interface{ TLSTerminates() bool }); ok && tt.TLSTerminates() {
		t.Fatal("built-in postgres endpoint satisfies TLSTerminates(); it would be misrouted to the plugin SNI dispatch path on :443")
	}
}
