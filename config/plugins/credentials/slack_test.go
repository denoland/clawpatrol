package credentials

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config/runtime"
)

type fakeInteractiveHITL struct {
	result runtime.HITLResolveResult

	mu       sync.Mutex
	id       string
	decision runtime.HITLDecision
}

func (f *fakeInteractiveHITL) Add(runtime.HITLPending) (string, <-chan runtime.HITLDecision) {
	return "", make(chan runtime.HITLDecision)
}

func (f *fakeInteractiveHITL) Discard(string) {}

func (f *fakeInteractiveHITL) Decide(id string, decision runtime.HITLDecision) bool {
	return f.DecideWithResult(id, decision).OK
}

func (f *fakeInteractiveHITL) DecideWithResult(id string, decision runtime.HITLDecision) runtime.HITLResolveResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.id = id
	f.decision = decision
	return f.result
}

func TestApplySlackInteractivePayloadReportsClientDisconnected(t *testing.T) {
	posted := make(chan slackResponseURLRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var req slackResponseURLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode response_url body: %v", err)
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		posted <- req
		_, _ = rw.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	pool := &fakeInteractiveHITL{result: runtime.HITLResolveResult{
		OK:     false,
		State:  runtime.HITLStateClientDisconnected,
		Reason: "original client connection closed before approval; upstream request was not sent",
	}}
	ack := applySlackInteractivePayload(runtime.WebhookCtx{HITL: pool}, slackInteractivePayload(t, srv.URL, "approve", "pending-1"))
	if len(ack) != 0 {
		t.Fatalf("ack = %#v, want empty map", ack)
	}

	select {
	case req := <-posted:
		if !req.ReplaceOriginal {
			t.Fatal("response_url payload did not request replace_original")
		}
		if !strings.Contains(req.Text, "Request is no longer active") {
			t.Fatalf("response_url text = %q, want client disconnect explanation", req.Text)
		}
		if !strings.Contains(req.Text, "upstream request was not sent") {
			t.Fatalf("response_url text = %q, want upstream not sent explanation", req.Text)
		}
		for _, block := range req.Blocks {
			if block["type"] == "actions" {
				t.Fatalf("response_url blocks still contain actions block: %#v", req.Blocks)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Slack response_url update was not posted")
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.id != "pending-1" {
		t.Fatalf("decided id = %q, want pending-1", pool.id)
	}
	if !pool.decision.Allow {
		t.Fatal("decision Allow = false, want true")
	}
	if pool.decision.By != "slack:U123" {
		t.Fatalf("decision By = %q, want slack:U123", pool.decision.By)
	}
}

func TestSlackHITLStatusExplainsTerminalStates(t *testing.T) {
	tests := []struct {
		name   string
		result runtime.HITLResolveResult
		want   string
	}{
		{
			name:   "timed out",
			result: runtime.HITLResolveResult{State: runtime.HITLStateTimedOut},
			want:   "Approval expired",
		},
		{
			name:   "already approved",
			result: runtime.HITLResolveResult{State: runtime.HITLStateApproved},
			want:   "already approved",
		},
		{
			name:   "already denied",
			result: runtime.HITLResolveResult{State: runtime.HITLStateDenied},
			want:   "already denied",
		},
		{
			name:   "unknown",
			result: runtime.HITLResolveResult{State: runtime.HITLStateUnknown},
			want:   "Already resolved or expired",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slackHITLStatus(tt.result, true, "U123")
			if !strings.Contains(got, tt.want) {
				t.Fatalf("status = %q, want substring %q", got, tt.want)
			}
		})
	}
}

type slackResponseURLRequest struct {
	ReplaceOriginal bool             `json:"replace_original"`
	Text            string           `json:"text"`
	Blocks          []map[string]any `json:"blocks"`
}

func slackInteractivePayload(t *testing.T, responseURL, actionID, pendingID string) []byte {
	t.Helper()
	payload := map[string]any{
		"user":         map[string]any{"name": "U123"},
		"response_url": responseURL,
		"actions": []map[string]any{
			{"action_id": actionID, "value": pendingID},
		},
		"message": map[string]any{
			"blocks": []map[string]any{
				{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "pending"}},
				{"type": "actions"},
			},
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}
