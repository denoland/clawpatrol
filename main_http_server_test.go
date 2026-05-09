package main

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
)

func TestLogHTTPServerExitLogsUnexpectedErrors(t *testing.T) {
	var buf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOut)

	logHTTPServerExit("dashboard", "127.0.0.1:1", errors.New("bind failed"))

	got := buf.String()
	if !strings.Contains(got, "dashboard http server on 127.0.0.1:1 stopped: bind failed") {
		t.Fatalf("log output = %q", got)
	}
}

func TestLogHTTPServerExitIgnoresServerClosed(t *testing.T) {
	var buf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOut)

	logHTTPServerExit("dashboard", "127.0.0.1:1", http.ErrServerClosed)

	if got := buf.String(); got != "" {
		t.Fatalf("log output = %q, want empty", got)
	}
}
