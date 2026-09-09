package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTeeGatewayLogAppendsToFile(t *testing.T) {
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev) })

	path := filepath.Join(t.TempDir(), "gateway.log")
	if err := os.WriteFile(path, []byte("existing line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := teeGatewayLog(path); err != nil {
		t.Fatalf("teeGatewayLog: %v", err)
	}
	log.Printf("hello from test")
	log.SetOutput(prev)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "existing line\n") {
		t.Fatalf("file was truncated: %q", got)
	}
	if !strings.Contains(string(got), "hello from test") {
		t.Fatalf("log line missing from file: %q", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
	}
}

func TestTeeGatewayLogMissingDir(t *testing.T) {
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev) })
	if err := teeGatewayLog(filepath.Join(t.TempDir(), "missing", "gateway.log")); err == nil {
		t.Fatal("expected an error for a missing parent directory")
	}
}

func TestLogTeeWritesAllSinksDespiteFailure(t *testing.T) {
	var good strings.Builder
	tee := logTee{failingWriter{}, &good}
	n, err := tee.Write([]byte("line\n"))
	if err != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if good.String() != "line\n" {
		t.Fatalf("second sink got %q", good.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }
