package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// AuditSink receives the append-only copy of persisted gateway events.
// Implementations should be best-effort: the primary sqlite event log
// and live dashboard stream must keep working even if the external
// audit path is unavailable.
type AuditSink interface {
	WriteAuditEvent(Event, []byte) error
}

// JSONLAuditSink appends one compact JSON Event per line. Operators can
// ship this file to S3 / object storage with their existing log forwarder
// while Claw Patrol keeps sqlite for the dashboard query path.
type JSONLAuditSink struct {
	mu sync.Mutex
	f  *os.File
}

func NewJSONLAuditSink(path string) (*JSONLAuditSink, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log open: %w", err)
	}
	return &JSONLAuditSink{f: f}, nil
}

func (s *JSONLAuditSink) WriteAuditEvent(ev Event, raw []byte) error {
	if s == nil || s.f == nil {
		return nil
	}
	if len(raw) == 0 {
		var err error
		raw, err = json.Marshal(ev)
		if err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(raw); err != nil {
		return err
	}
	_, err := s.f.Write([]byte("\n"))
	return err
}

func (s *JSONLAuditSink) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	return s.f.Close()
}
