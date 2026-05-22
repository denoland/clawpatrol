package main

// HITL async operation status API. mitmHTTPS exposes long-running
// approval flows by returning a polling URL pointing at
// /api/hitl/operations/<id>/status; this file owns the constants
// describing that URL shape, the GET handler that serves it, and the
// response-shaping helpers shared by both the GET handler and the
// in-line "202 Accepted" path that mitmHTTPS uses when it first
// creates a pending operation.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	hitlOperationStatusPrefix       = "/api/hitl/operations/"
	hitlOperationStatusSuffix       = "/status"
	hitlRetryOperationHeader        = "Clawpatrol-HITL-Operation"
	hitlDefaultRetryAfterSeconds    = 5
	hitlOperationNotFoundErrorValue = "hitl_operation_not_found"
)

func (w *webMux) apiHITLOperationStatus(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, http.MethodGet, http.StatusMethodNotAllowed)
		return
	}
	store := NewHITLOperationStore(w.g.db)
	var op HITLOperation
	var err error
	statusToken := r.URL.Query().Get("token")
	if statusToken != "" {
		operationID, ok := hitlOperationIDFromStatusPath(r.URL.Path)
		if !ok {
			writeHITLOperationNotFound(rw)
			return
		}
		op, err = store.GetForStatusToken(r.Context(), operationID, statusToken)
		if err == nil {
			op.StatusToken = statusToken
		} else if !errors.Is(err, ErrHITLOperationNotFound) {
			log.Printf("hitl operation status %s: %v", operationID, err)
			http.Error(rw, "failed to load HITL operation", http.StatusInternalServerError)
			return
		} else if bearerFromAuthHeader(r.Header.Get("Authorization")) == "" {
			writeHITLOperationNotFound(rw)
			return
		}
	}
	if op.ID == "" {
		if isFunnelPublicRequest(r.Context()) {
			writeHITLOperationNotFound(rw)
			return
		}
		token := bearerFromAuthHeader(r.Header.Get("Authorization"))
		peerIP := peerIPForAPIToken(w.g.db, token)
		if peerIP == "" {
			http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
			return
		}
		operationID, ok := hitlOperationIDFromStatusPath(r.URL.Path)
		if !ok {
			writeHITLOperationNotFound(rw)
			return
		}
		profileID := w.g.profileFor(peerIP)
		principalID := hitlPeerPrincipalID(peerIP)
		op, err = store.GetForPrincipal(r.Context(), operationID, profileID, principalID)
	}
	if errors.Is(err, ErrHITLOperationNotFound) {
		writeHITLOperationNotFound(rw)
		return
	}
	if err != nil {
		http.Error(rw, "load hitl operation", http.StatusInternalServerError)
		return
	}
	writeHITLOperationStatus(rw, op, w.hitlPublicURL())
}

func (w *webMux) hitlPublicURL() string {
	// Prefer the live config — public_url may be auto-derived from the
	// tsnet Funnel cert AFTER webMux is constructed.
	if w.g != nil && w.g.cfg != nil && w.g.cfg.PublicURL() != "" {
		return w.g.cfg.PublicURL()
	}
	return w.publicURL
}

func hitlOperationIDFromStatusPath(path string) (string, bool) {
	if !strings.HasPrefix(path, hitlOperationStatusPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(path, hitlOperationStatusPrefix)
	if !strings.HasSuffix(rest, hitlOperationStatusSuffix) {
		return "", false
	}
	rawID := strings.TrimSuffix(rest, hitlOperationStatusSuffix)
	if rawID == "" || strings.Contains(rawID, "/") {
		return "", false
	}
	id, err := url.PathUnescape(rawID)
	if err != nil || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func hitlPeerPrincipalID(peerIP string) string {
	return "peer:" + peerIP
}

func writeHITLOperationAccepted(rw http.ResponseWriter, op HITLOperation, publicURL string) {
	statusURL := hitlOperationStatusURL(publicURL, op.ID, op.StatusToken)
	rw.Header().Set("Location", statusURL)
	rw.Header().Set("Retry-After", strconv.Itoa(hitlDefaultRetryAfterSeconds))
	writeHITLOperationResponse(rw, http.StatusAccepted, op, statusURL)
}

func writeHITLOperationStatus(rw http.ResponseWriter, op HITLOperation, publicURL string) {
	statusURL := hitlOperationStatusURL(publicURL, op.ID, op.StatusToken)
	writeHITLOperationResponse(rw, http.StatusOK, op, statusURL)
}

func writeHITLOperationResponse(rw http.ResponseWriter, status int, op HITLOperation, statusURL string) {
	upstreamCalled := hitlOperationUpstreamCalled(op)
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.Header().Set("Clawpatrol-HITL-State", string(op.State))
	rw.Header().Set("Clawpatrol-Upstream-Called", strconv.FormatBool(upstreamCalled))
	if op.State == HITLOperationStatePendingApproval || op.State == HITLOperationStateSyncWaiting {
		rw.Header().Set("Retry-After", strconv.Itoa(hitlDefaultRetryAfterSeconds))
	}
	body := hitlOperationStatusBody(op, statusURL, upstreamCalled)
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(body)
}

func hitlOperationStatusBody(op HITLOperation, statusURL string, upstreamCalled bool) map[string]any {
	body := map[string]any{
		"operation_id":    op.ID,
		"state":           string(op.State),
		"status_url":      statusURL,
		"upstream_called": upstreamCalled,
		"terminal":        isTerminalHITLOperationState(op.State),
		"message":         hitlOperationStatusMessage(op.State),
	}

	switch op.State {
	case HITLOperationStateSyncWaiting, HITLOperationStatePendingApproval:
		body["retry_original_request"] = true
		if !op.ApprovalExpiresAt.IsZero() {
			body["approval_expires_at"] = op.ApprovalExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	case HITLOperationStateApprovedWaitingForRetry:
		body["retry_original_request"] = true
		body["retry_header_name"] = hitlRetryOperationHeader
		body["retry_header_value"] = op.ID
		if op.RetryExpiresAt != nil {
			body["retry_expires_at"] = op.RetryExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	case HITLOperationStateExpired:
		if op.ExpiredReason != "" {
			body["expired_reason"] = op.ExpiredReason
		}
	case HITLOperationStateUpstreamSucceeded, HITLOperationStateUpstreamFailed:
		if op.TerminalAt != nil {
			body["completed_at"] = op.TerminalAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return body
}

func hitlOperationStatusMessage(state HITLOperationState) string {
	switch state {
	case HITLOperationStateSyncWaiting:
		return "This request is waiting for human approval. Claw Patrol has not called the upstream service yet."
	case HITLOperationStatePendingApproval:
		return "This request is waiting for human approval. Claw Patrol has not called the upstream service, so no upstream side effect has been executed. Poll status_url until the state changes. If the state becomes approved_waiting_for_retry, retry the same original request with Clawpatrol-HITL-Operation before retry_expires_at."
	case HITLOperationStateApprovedWaitingForRetry:
		return "Human approval has been granted. Claw Patrol has not called upstream yet. Retry the same original request with Clawpatrol-HITL-Operation before retry_expires_at to execute it."
	case HITLOperationStateDenied:
		return "Human approval was denied. Claw Patrol did not call upstream."
	case HITLOperationStateExpired:
		return "Human approval or retry time expired. Claw Patrol did not call upstream."
	case HITLOperationStateExecutingUpstream:
		return "The approved retry is being forwarded upstream now."
	case HITLOperationStateUpstreamSucceeded:
		return "The approved request completed upstream."
	case HITLOperationStateUpstreamFailed:
		return "The approved retry reached the forwarding attempt, but Claw Patrol could not confirm success."
	case HITLOperationStateClientDisconnected:
		return "The original client connection closed before Claw Patrol could return an async polling handle. Upstream was not called."
	default:
		return "HITL operation status is available."
	}
}

func hitlOperationUpstreamCalled(op HITLOperation) bool {
	if op.UpstreamCalled {
		return true
	}
	switch op.State {
	case HITLOperationStateExecutingUpstream, HITLOperationStateUpstreamSucceeded, HITLOperationStateUpstreamFailed:
		return true
	default:
		return false
	}
}

func hitlOperationStatusURL(publicURL, operationID, statusToken string) string {
	base := strings.TrimRight(publicURL, "/")
	path := hitlOperationStatusPrefix + url.PathEscape(operationID) + hitlOperationStatusSuffix
	if statusToken != "" {
		path += "?token=" + url.QueryEscape(statusToken)
	}
	if base == "" {
		return path
	}
	return base + path
}

func writeHITLOperationNotFound(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(rw).Encode(map[string]any{"error": hitlOperationNotFoundErrorValue})
}
