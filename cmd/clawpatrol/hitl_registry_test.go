package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config/runtime"
)

func TestHITLRegistryAsyncPendingApprovalCreatesRetryGrantInsteadOfSendingChannelDecision(t *testing.T) {
	registry := newHITLRegistry(nil)
	var gotOp string
	var gotDecision runtime.HITLDecision
	registry.asyncGrantResolver = func(operationID string, d runtime.HITLDecision) runtime.HITLResolveResult {
		gotOp = operationID
		gotDecision = d
		return runtime.HITLResolveResult{OK: true, State: runtime.HITLStateApproved, Reason: "retry grant created"}
	}
	id, ch := registry.Add(runtime.HITLPending{
		OperationID:    "op_123",
		OperationState: runtime.HITLOperationStatePendingApproval,
		ApprovalEffect: runtime.HITLApprovalEffectCreateRetryGrant,
		Host:           "api.example.test",
		Method:         "POST",
		Path:           "/v1/write",
		CreatedAt:      time.Now(),
	})

	result := registry.DecideWithResult(id, runtime.HITLDecision{Allow: true, By: "dashboard"})
	if !result.OK {
		t.Fatalf("DecideWithResult OK = false, want true: %#v", result)
	}
	if gotOp != "op_123" {
		t.Fatalf("async resolver operationID = %q, want op_123", gotOp)
	}
	if !gotDecision.Allow || gotDecision.By != "dashboard" {
		t.Fatalf("async resolver decision = %#v, want dashboard approval", gotDecision)
	}
	select {
	case decision := <-ch:
		t.Fatalf("decision channel received %#v; async pending approval must not execute upstream directly", decision)
	default:
	}
}

func TestHITLRegistryDecideWithResultRecordsTerminalState(t *testing.T) {
	registry := newHITLRegistry(nil)
	id, ch := registry.Add(runtime.HITLPending{
		Host:      "api.example.test",
		Method:    "POST",
		Path:      "/v1/write",
		CreatedAt: time.Now(),
	})

	result := registry.DecideWithResult(id, runtime.HITLDecision{Allow: true, By: "dashboard"})
	if !result.OK {
		t.Fatalf("DecideWithResult OK = false, want true: %#v", result)
	}
	if result.State != runtime.HITLStateApproved {
		t.Fatalf("DecideWithResult State = %q, want %q", result.State, runtime.HITLStateApproved)
	}
	select {
	case decision := <-ch:
		if !decision.Allow || decision.By != "dashboard" {
			t.Fatalf("decision = %#v, want approved by dashboard", decision)
		}
	case <-time.After(time.Second):
		t.Fatal("decision channel did not receive approval")
	}

	stale := registry.DecideWithResult(id, runtime.HITLDecision{Allow: false, By: "slack:U123"})
	if stale.OK {
		t.Fatalf("stale DecideWithResult OK = true, want false")
	}
	if stale.State != runtime.HITLStateApproved {
		t.Fatalf("stale State = %q, want %q", stale.State, runtime.HITLStateApproved)
	}
	if !strings.Contains(stale.Reason, "dashboard") {
		t.Fatalf("stale Reason = %q, want original decision maker", stale.Reason)
	}
}

func TestHITLRegistryCancelAfterDecisionKeepsApprovedTerminalState(t *testing.T) {
	registry := newHITLRegistry(nil)
	id, ch := registry.Add(runtime.HITLPending{
		Host:      "api.example.test",
		Method:    "POST",
		Path:      "/v1/write",
		CreatedAt: time.Now(),
	})

	result := registry.DecideWithResult(id, runtime.HITLDecision{Allow: true, By: "dashboard"})
	if !result.OK {
		t.Fatalf("DecideWithResult OK = false, want true: %#v", result)
	}
	cancel := registry.Cancel(id, runtime.HITLStateTimedOut, "timed out after approval")
	if cancel.OK {
		t.Fatalf("Cancel after decision OK = true, want false")
	}
	if cancel.State != runtime.HITLStateApproved {
		t.Fatalf("Cancel after decision State = %q, want %q", cancel.State, runtime.HITLStateApproved)
	}
	select {
	case decision := <-ch:
		if !decision.Allow || decision.By != "dashboard" {
			t.Fatalf("decision = %#v, want approved by dashboard", decision)
		}
	default:
		t.Fatal("decision channel lost approval after stale cancel")
	}
}

func TestHITLRegistryCancelRecordsClientDisconnected(t *testing.T) {
	registry := newHITLRegistry(nil)
	id, ch := registry.Add(runtime.HITLPending{
		Host:      "api.example.test",
		Method:    "POST",
		Path:      "/v1/write",
		CreatedAt: time.Now(),
	})

	reason := "original client connection closed before approval; upstream request was not sent"
	result := registry.Cancel(id, runtime.HITLStateClientDisconnected, reason)
	if !result.OK {
		t.Fatalf("Cancel OK = false, want true: %#v", result)
	}
	if result.State != runtime.HITLStateClientDisconnected {
		t.Fatalf("Cancel State = %q, want %q", result.State, runtime.HITLStateClientDisconnected)
	}
	select {
	case decision := <-ch:
		t.Fatalf("Cancel delivered decision %#v, want no human decision", decision)
	default:
	}

	stale := registry.DecideWithResult(id, runtime.HITLDecision{Allow: true, By: "slack:U123"})
	if stale.OK {
		t.Fatal("stale approve after client disconnect OK = true, want false")
	}
	if stale.State != runtime.HITLStateClientDisconnected {
		t.Fatalf("stale State = %q, want %q", stale.State, runtime.HITLStateClientDisconnected)
	}
	if !strings.Contains(stale.Reason, "upstream request was not sent") {
		t.Fatalf("stale Reason = %q, want upstream-not-sent explanation", stale.Reason)
	}
}

func TestAPIHITLDecideReturnsStructuredTerminalState(t *testing.T) {
	registry := newHITLRegistry(nil)
	id, _ := registry.Add(runtime.HITLPending{
		Host:      "api.example.test",
		Method:    "POST",
		Path:      "/v1/write",
		CreatedAt: time.Now(),
	})
	reason := "original client connection closed before approval; upstream request was not sent"
	registry.Cancel(id, runtime.HITLStateClientDisconnected, reason)

	w := &webMux{g: &Gateway{hitl: registry}}
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decide", strings.NewReader(fmt.Sprintf(`{"id":%q,"allow":true}`, id)))
	req = req.WithContext(contextWithPrincipal(req.Context(), principal{Kind: principalDashboardPassword, Owner: "operator"}))
	w.apiHITLDecide(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rw.Code, http.StatusOK, rw.Body.String())
	}
	var result runtime.HITLResolveResult
	if err := json.NewDecoder(rw.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.OK {
		t.Fatal("api result OK = true, want false for stale terminal state")
	}
	if result.State != runtime.HITLStateClientDisconnected {
		t.Fatalf("api result State = %q, want %q", result.State, runtime.HITLStateClientDisconnected)
	}
	if !strings.Contains(result.Reason, "upstream request was not sent") {
		t.Fatalf("api result Reason = %q, want upstream-not-sent explanation", result.Reason)
	}
}
