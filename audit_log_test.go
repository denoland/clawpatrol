package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJSONLAuditSinkWritesPersistentEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	audit, err := NewJSONLAuditSink(path)
	if err != nil {
		t.Fatalf("NewJSONLAuditSink: %v", err)
	}
	defer func() { _ = audit.Close() }()

	s, err := NewSinkWithAudit(nil, 4, audit)
	if err != nil {
		t.Fatalf("NewSinkWithAudit: %v", err)
	}
	defer close(s.ch)

	ch, cancel := s.Subscribe()
	defer cancel()

	const id = "req-audit"
	s.Emit(Event{ID: id, Phase: "start", Mode: "mitm", Host: "api.example.com"})
	s.Emit(Event{ID: id, Phase: "end", Mode: "mitm", Host: "api.example.com", Action: "allow", Status: 200, ReqBody: "redacted sample"})

	for seen := 0; seen < 2; seen++ {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for sink fan-out")
		}
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	var lines []Event
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("invalid audit JSONL line: %v", err)
		}
		lines = append(lines, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("audit log lines = %d, want 1", len(lines))
	}
	if lines[0].ID != id || lines[0].Phase != "end" || lines[0].Action != "allow" || lines[0].ReqBody != "redacted sample" {
		t.Fatalf("unexpected audit event: %+v", lines[0])
	}
}

func TestJSONLAuditSinkCreatesOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := NewJSONLAuditSink(path)
	if err != nil {
		t.Fatalf("NewJSONLAuditSink: %v", err)
	}
	defer func() { _ = audit.Close() }()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("audit log mode = %#o, want 0600", got)
	}
}
