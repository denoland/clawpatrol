package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

func TestMITMRequestReadErrorLogIsSanitizedAndBounded(t *testing.T) {
	const (
		headerMarker = "SYNTHETIC_HEADER_MARKER"
		headerSuffix = "SYNTHETIC_HEADER_SUFFIX"
		bodyMarker   = "SYNTHETIC_BODY_MARKER"
		bodySuffix   = "SYNTHETIC_BODY_SUFFIX"
		maxLogBytes  = 512
	)

	tests := []struct {
		name    string
		payload string
		markers []string
	}{
		{
			name:    "malformed header",
			payload: "GET / HTTP/1.1\r\nX-Test: " + headerMarker + "\x00" + headerSuffix + "\r\n\r\n",
			markers: []string{headerMarker, headerSuffix},
		},
		{
			name:    "body bytes parsed as a request line",
			payload: bodyMarker + strings.Repeat("x", 32<<10) + bodySuffix + "\r\n",
			markers: []string{bodyMarker, bodySuffix},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runMalformedMITMRequest(t, tt.payload)
			for _, marker := range tt.markers {
				if strings.Contains(got, marker) {
					t.Fatalf("log leaked synthetic request marker %q: %q", marker, got)
				}
			}
			if len(got) > maxLogBytes {
				t.Fatalf("log length = %d bytes, want <= %d", len(got), maxLogBytes)
			}
			if lines := strings.Count(got, "\n"); lines != 1 {
				t.Fatalf("log has %d lines, want exactly one: %q", lines, got)
			}
			if !strings.Contains(got, "mitm_request_read_error") {
				t.Fatalf("log = %q, want structured event name", got)
			}
			if !strings.Contains(got, "host=\"api.example.test\"") {
				t.Fatalf("log = %q, want endpoint host metadata", got)
			}
			if !strings.Contains(got, "reason=invalid_request") {
				t.Fatalf("log = %q, want sanitized reason", got)
			}
		})
	}
}

func TestMITMRequestReadErrorReasonUsesFixedCategories(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "incomplete", err: io.ErrUnexpectedEOF, want: "incomplete_request"},
		{name: "too large", err: bufio.ErrBufferFull, want: "request_too_large"},
		{name: "timeout", err: &net.DNSError{IsTimeout: true}, want: "timeout"},
		{name: "network", err: &net.DNSError{Err: "SYNTHETIC_NETWORK_MARKER"}, want: "network_error"},
		{name: "parser", err: errors.New("SYNTHETIC_PARSER_MARKER"), want: "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mitmRequestReadErrorReason(tt.err); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeMITMRequestReadLogHost(t *testing.T) {
	const suffix = "SYNTHETIC_HOST_SUFFIX"
	host := "api.example.test\r\ninjected=true" + strings.Repeat("x", maxMITMRequestReadLogHostBytes) + suffix
	got := sanitizeMITMRequestReadLogHost(host)
	if len(got) > maxMITMRequestReadLogHostBytes {
		t.Fatalf("sanitized host length = %d, want <= %d", len(got), maxMITMRequestReadLogHostBytes)
	}
	if strings.ContainsAny(got, "\r\n=\"") {
		t.Fatalf("sanitized host contains log-structure characters: %q", got)
	}
	if strings.Contains(got, suffix) {
		t.Fatalf("sanitized host retained truncated suffix: %q", got)
	}
}

func runMalformedMITMRequest(t *testing.T, payload string) string {
	t.Helper()

	certs, _ := inMemoryCertCache(t)
	g := &Gateway{certs: certs}
	g.cfg.Store(&config.Gateway{Policy: &config.Policy{}})
	ep := &config.CompiledEndpoint{}

	var logs bytes.Buffer
	oldOutput := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.mitmHTTPS(serverConn, "api.example.test", ep)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "api.example.test",
	})
	deadline := time.Now().Add(2 * time.Second)
	if err := clientTLS.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := io.WriteString(clientTLS, payload); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}
	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after malformed request")
	}
	return logs.String()
}
