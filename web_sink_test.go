package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestSinkAssignsIDToPersistentEvents(t *testing.T) {
	s, err := NewSink(nil, 4)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(s.ch)

	ch, cancel := s.Subscribe()
	defer cancel()

	s.Emit(Event{Mode: "pg", AgentIP: "100.64.0.1", Host: "db", Method: "SELECT", Path: "SELECT 1"})

	select {
	case pkt := <-ch:
		if pkt.ev.ID == "" {
			t.Fatal("fan-out event ID is empty")
		}
		var ev Event
		if err := json.Unmarshal(pkt.raw, &ev); err != nil {
			t.Fatalf("unmarshal raw event: %v", err)
		}
		if ev.ID == "" {
			t.Fatal("raw SSE event ID is empty")
		}
		if ev.ID != pkt.ev.ID {
			t.Fatalf("raw ID %q != packet ID %q", ev.ID, pkt.ev.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestSinkPersistsGeneratedID(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	s, err := NewSink(db, 4)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(s.ch)

	ch, cancel := s.Subscribe()
	defer cancel()

	s.Emit(Event{Mode: "pg", AgentIP: "100.64.0.1", Host: "db", Method: "SELECT", Path: "SELECT 1"})

	var id string
	select {
	case pkt := <-ch:
		id = pkt.ev.ID
		if id == "" {
			t.Fatal("fan-out event ID is empty")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}

	var persisted string
	if err := db.QueryRow("SELECT action_id FROM actions WHERE host = ?", "db").Scan(&persisted); err != nil {
		t.Fatalf("query action_id: %v", err)
	}
	if persisted != id {
		t.Fatalf("persisted action_id %q != fan-out ID %q", persisted, id)
	}
}

func TestSinkPreservesExistingPersistentEventID(t *testing.T) {
	s, err := NewSink(nil, 4)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(s.ch)

	ch, cancel := s.Subscribe()
	defer cancel()

	const id = "req-existing"
	s.Emit(Event{ID: id, Phase: "end", Mode: "mitm", AgentIP: "100.64.0.1", Host: "api.example.com"})

	select {
	case pkt := <-ch:
		if pkt.ev.ID != id {
			t.Fatalf("ID = %q, want %q", pkt.ev.ID, id)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}
