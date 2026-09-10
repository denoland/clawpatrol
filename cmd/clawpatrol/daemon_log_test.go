package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLastLogLineSince(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	old := "daemon pid=1 starting\ndaemon: old failure\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	off := int64(len(old))

	if got := lastLogLineSince(path, off); got != "" {
		t.Fatalf("nothing appended yet, got %q", got)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("daemon pid=2 starting\ndaemon: transport: no mode file — re-run `clawpatrol join`\n\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	want := "daemon: transport: no mode file — re-run `clawpatrol join`"
	if got := lastLogLineSince(path, off); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := lastLogLineSince(path, 0); got != want {
		t.Fatalf("from start: got %q, want %q", got, want)
	}
	if got := lastLogLineSince(filepath.Join(t.TempDir(), "absent"), 0); got != "" {
		t.Fatalf("missing file: got %q", got)
	}
}

func TestLastLogLineSinceReadsTheTailOfALongBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	if err := os.WriteFile(path, []byte("old daemon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	off := int64(len("old daemon\n"))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		_, _ = f.WriteString("debug: a chatty line of startup output that repeats\n") // ~100 KiB total
	}
	_, _ = f.WriteString("daemon: transport: the real reason\n")
	_ = f.Close()
	if got := lastLogLineSince(path, off); got != "daemon: transport: the real reason" {
		t.Fatalf("got %q", got)
	}
}
