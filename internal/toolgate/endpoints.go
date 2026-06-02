package toolgate

// HTTP endpoints clawpatrol exposes for the agent-side polling half
// of the HITL multi-turn dance. Three shapes are wired (long-poll, SSE,
// WebSocket). The gateway-initiated follow-up (followup.go) instructs
// the model to long-poll `POST /api/approval/poll` using whichever of
// the agent's own tools can make an HTTP request; the SSE + WS handlers
// are wired but degrade to long-poll semantics so a curious agent gets
// the same verdict shape regardless of which it picked.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultPollTimeout caps a single long-poll hold. Tuned to be short
// enough that mid-flight connection-tracking (LB / NAT) doesn't
// reap an idle TCP conn, but long enough that a normal "human
// looked at the dashboard and clicked" scenario doesn't bounce the
// agent through retries. Re-polling is the agent's job, not the
// gateway's, so 30s is a reasonable midpoint.
const DefaultPollTimeout = 30 * time.Second

// PollResponse is the JSON the agent's polling tool sees. State is
// one of "pending" (long-poll timed out — re-poll), "approved", or
// "denied". For approved / denied, Token is echoed back so the gateway
// can correlate the agent's next turn's tool_result with the parked
// call (when the agent reflects the polling tool result back to the
// LLM, clawpatrol intercepts and swaps with the actual response).
type PollResponse struct {
	State string `json:"state"`
	Token string `json:"token,omitempty"`
	By    string `json:"by,omitempty"`
}

// Mux registers all three approval endpoints on the supplied mux.
// The base path is "/api/approval"; each shape lives at a single-
// segment suffix under it. Callers (the dashboard webserver) wire
// auth in front of the returned handlers — for the draft, any caller
// holding the opaque token is allowed; v2 will bind tokens to the
// agent that owns them.
func Mux(s *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/approval/poll", s.handlePoll)
	mux.HandleFunc("/api/approval/sse", s.handleSSE)
	mux.HandleFunc("/api/approval/ws", s.handleWS)
	mux.HandleFunc("/api/approval/decide", s.handleDecide)
	mux.HandleFunc("/api/approval/pending", s.handlePending)
	return mux
}

// extractToken pulls the token out of (in priority order) a JSON body
// field, a `token=` query param, or a `Bearer` header. Three shapes
// because each transport has a different idiomatic carrier and the
// polling tool the LLM picks may not match the one clawpatrol injected.
func extractToken(r *http.Request) string {
	if r.Body != nil {
		if r.Header.Get("Content-Type") == "application/json" {
			var body struct {
				Token string `json:"token"`
			}
			// Limit-read to defang a hostile / runaway agent.
			dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096))
			if err := dec.Decode(&body); err == nil && body.Token != "" {
				return body.Token
			}
		}
	}
	if q := r.URL.Query().Get("token"); q != "" {
		return q
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func (s *Store) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := extractToken(r)
	pc := s.Lookup(token)
	if pc == nil {
		http.Error(w, "unknown token", http.StatusNotFound)
		return
	}
	if state, ok := pc.State(); ok {
		writeJSON(w, http.StatusOK, PollResponse{
			State: stateName(state),
			Token: token,
			By:    pc.By(),
		})
		return
	}
	timeout := DefaultPollTimeout
	if hdr := r.Header.Get("X-Poll-Timeout-Seconds"); hdr != "" {
		// Clamp to [1, 120] — the gateway's own read deadlines impose
		// a hard upper bound, and a 0 / negative would degenerate into
		// "return immediately" which the caller can already get by
		// inspecting State synchronously.
		var seconds int
		if _, err := fmt.Sscanf(hdr, "%d", &seconds); err == nil {
			if seconds < 1 {
				seconds = 1
			}
			if seconds > 120 {
				seconds = 120
			}
			timeout = time.Duration(seconds) * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	select {
	case <-pc.Decided():
		state, _ := pc.State()
		writeJSON(w, http.StatusOK, PollResponse{
			State: stateName(state),
			Token: token,
			By:    pc.By(),
		})
	case <-ctx.Done():
		writeJSON(w, http.StatusOK, PollResponse{
			State: "pending",
			Token: token,
		})
	}
}

// handleSSE is the SSE-shaped variant. Per the spec, the gateway
// holds the connection open and emits a single event when the
// verdict is in. The draft writes "event: pending" once on connect
// so curious agents see liveness without having to wait for the
// human, then a final "event: verdict" with the JSON payload.
//
// TODO(v2): proper retry hints, last-event-id semantics, flush
// throttling per upstream LB / proxy behaviour.
func (s *Store) handleSSE(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	pc := s.Lookup(token)
	if pc == nil {
		http.Error(w, "unknown token", http.StatusNotFound)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	_, _ = fmt.Fprintf(w, "event: pending\ndata: {\"token\":%q}\n\n", token)
	flusher.Flush()

	select {
	case <-pc.Decided():
	case <-r.Context().Done():
		return
	}
	state, _ := pc.State()
	payload, _ := json.Marshal(PollResponse{
		State: stateName(state),
		Token: token,
		By:    pc.By(),
	})
	_, _ = fmt.Fprintf(w, "event: verdict\ndata: %s\n\n", payload)
	flusher.Flush()
}

// handleWS is the websocket-shaped variant. Stubbed in the draft —
// a real websocket upgrade needs a handshake-aware buffered conn
// and ping/pong management that the existing gateway WS upgrade
// path (cmd/clawpatrol/ws.go) handles for credential-injected
// upstream WS but not for clawpatrol-terminated WS. Returns 501
// with a JSON pointer at the long-poll endpoint so curious agents
// can fall back.
//
// TODO(v2): proper websocket handler. nhooyr.io/websocket or
// gorilla, depending on which the gateway already vendors.
func (s *Store) handleWS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = fmt.Fprintf(w, `{"error":"ws not implemented in draft","fallback":"/api/approval/poll"}`)
}

// handleDecide is the dashboard-side approve/deny endpoint. In the
// final shape, this is invoked by the existing dashboard HITL
// approval surface (see cl-99t) rather than the operator calling it
// directly. Body: {"token": "...", "decision": "approve"|"deny", "by": "..."}.
//
// Auth note: the regular dashboardAuthGate wraps this endpoint when
// it's mounted under the web mux, so the bearer-token leg is unused
// in practice. Standalone (test harness) callers get no auth.
func (s *Store) handleDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Token    string `json:"token"`
		Decision string `json:"decision"`
		By       string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	pc := s.Lookup(body.Token)
	if pc == nil {
		http.Error(w, "unknown token", http.StatusNotFound)
		return
	}
	var v Verdict
	switch body.Decision {
	case "approve", "allow":
		v = VerdictAllow
	case "deny", "reject":
		v = VerdictDeny
	default:
		http.Error(w, "bad decision", http.StatusBadRequest)
		return
	}
	pc.Decide(v, body.By)
	writeJSON(w, http.StatusOK, PollResponse{
		State: stateName(v),
		Token: body.Token,
		By:    body.By,
	})
}

// handlePending lists currently-pending calls for the dashboard.
// Minimal payload — token, tool name, age, reason. The dashboard
// renders these into operator-facing approval cards.
func (s *Store) handlePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type entry struct {
		Token     string    `json:"token"`
		ToolName  string    `json:"tool_name"`
		Reason    string    `json:"reason"`
		ToolInput string    `json:"tool_input,omitempty"`
		Created   time.Time `json:"created"`
	}
	pending := s.Pending()
	out := make([]entry, 0, len(pending))
	for _, pc := range pending {
		out = append(out, entry{
			Token:     pc.Token,
			ToolName:  pc.ToolName,
			Reason:    pc.Reason,
			ToolInput: string(pc.ToolInput),
			Created:   pc.Created,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// stateName maps an internal Verdict to the wire-protocol verb the
// agent sees. "approved" / "denied" mirrors the existing HITL chain's
// dashboard event vocabulary; pending stays as-is.
func stateName(v Verdict) string {
	switch v {
	case VerdictAllow:
		return "approved"
	case VerdictDeny:
		return "denied"
	default:
		return "pending"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
