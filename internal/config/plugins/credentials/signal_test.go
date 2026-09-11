package credentials

// Tests for the signal_cli HITL notifier. testSecretStore is defined in
// slack_notify_test.go (same package) and reused here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func signalTestReq(store testSecretStore) runtime.ApproveRequest {
	return runtime.ApproveRequest{
		Secrets: store,
		Method:  "POST",
		Host:    "gitlab.com",
		Path:    "/api/v4/projects/1/issues",
		Profile: "uninfo",
	}
}

// withSignalClient points the notifier at a test server and disables the
// retry backoff, restoring both on cleanup.
func withSignalClient(t *testing.T, c *http.Client) {
	t.Helper()
	oldClient, oldBackoff := signalHTTPClient, signalRetryBackoff
	signalHTTPClient, signalRetryBackoff = c, 0
	t.Cleanup(func() { signalHTTPClient, signalRetryBackoff = oldClient, oldBackoff })
}

func TestSignalNotifyHITLSendsToV2Send(t *testing.T) {
	var gotPath, gotAuth string
	var payload struct {
		Number     string   `json:"number"`
		Recipients []string `json:"recipients"`
		Message    string   `json:"message"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}), runtime.HITLTarget{
		CredentialName: "signal-ops",
		Channel:        "+15551112222",
		PendingID:      "pending-9",
		DashboardURL:   "https://gateway.example",
	})
	if err != nil {
		t.Fatalf("NotifyHITL: %v", err)
	}
	if gotPath != "/v2/send" {
		t.Fatalf("path = %q, want /v2/send", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("unexpected Authorization header %q (no auth configured)", gotAuth)
	}
	if payload.Number != "+15550000000" {
		t.Fatalf("number = %q, want +15550000000", payload.Number)
	}
	if len(payload.Recipients) != 1 || payload.Recipients[0] != "+15551112222" {
		t.Fatalf("recipients = %v, want [+15551112222]", payload.Recipients)
	}
	for _, want := range []string{"clawpatrol:", "https://gateway.example/#hitl/pending-9"} {
		if !strings.Contains(payload.Message, want) {
			t.Fatalf("message = %q, want substring %q", payload.Message, want)
		}
	}
}

func TestSignalNotifyHITLBasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000", "auth": "rest:secretpw"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "+15551112222", PendingID: "p1", DashboardURL: "https://gw"})
	if err != nil {
		t.Fatalf("NotifyHITL: %v", err)
	}
	if !ok || user != "rest" || pass != "secretpw" {
		t.Fatalf("basic auth = %q/%q ok=%v, want rest/secretpw", user, pass, ok)
	}
}

func TestSignalNotifyHITLRetriesTransient5xx(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, `{"error":"busy"}`, http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "+15551112222", PendingID: "p1", DashboardURL: "https://gw"})
	if err != nil {
		t.Fatalf("NotifyHITL after retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestSignalNotifyHITLNoRetryOn4xx(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		http.Error(w, `{"error":"invalid recipient"}`, http.StatusBadRequest)
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "bad", PendingID: "p1", DashboardURL: "https://gw"})
	if err == nil {
		t.Fatal("NotifyHITL error = nil, want 4xx error")
	}
	if !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("error = %v, want the signal error body surfaced", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx must not retry)", attempts)
	}
}

func TestSignalNotifyHITLRequiresConfig(t *testing.T) {
	cases := map[string]struct {
		extras  map[string]string
		channel string
	}{
		"missing api_url": {map[string]string{"number": "+15550000000"}, "+15551112222"},
		"missing number":  {map[string]string{"api_url": "http://signal.invalid"}, "+15551112222"},
		"missing channel": {map[string]string{"api_url": "http://signal.invalid", "number": "+15550000000"}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
				"signal-ops": {Extras: tc.extras},
			}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: tc.channel, PendingID: "p1", DashboardURL: "https://gw"})
			if err == nil {
				t.Fatalf("%s: expected an error, got nil", name)
			}
		})
	}
}

// signalDeleteServer answers /v2/send with a fixed timestamp (string form,
// as the API returns it) and records the remote-delete calls that follow.
func signalDeleteServer(t *testing.T, sendTimestamp string) (*httptest.Server, *struct {
	Recipient string `json:"recipient"`
	Timestamp int64  `json:"timestamp"`
}, *int) {
	var deleted int
	var last struct {
		Recipient string `json:"recipient"`
		Timestamp int64  `json:"timestamp"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/send":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"timestamp":"` + sendTimestamp + `"}`))
		case strings.HasPrefix(r.URL.Path, "/v1/remote-delete/"):
			deleted++
			_ = json.NewDecoder(r.Body).Decode(&last)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server, &last, &deleted
}

const signalTestTimestamp = 1000000000000

// signalNotifyCapturingRef sends a prompt and returns the message ref the
// notifier handed to both update sinks.
func signalNotifyCapturingRef(t *testing.T, s *SignalCLI, store testSecretStore) (opRef, pendingRef string) {
	t.Helper()
	req := signalTestReq(store)
	req.AsyncOperationID = "op-1"
	err := s.NotifyHITL(context.Background(), req, runtime.HITLTarget{
		CredentialName: "signal-ops",
		Channel:        "+15551112222",
		PendingID:      "p1",
		DashboardURL:   "https://gw",
		MessageUpdateSink: func(_ context.Context, operationID, ref string) error {
			if operationID != "op-1" {
				t.Errorf("operation id = %q, want op-1", operationID)
			}
			opRef = ref
			return nil
		},
		PendingMessageUpdateSink: func(_ context.Context, pendingID, ref string) error {
			if pendingID != "p1" {
				t.Errorf("pending id = %q, want p1", pendingID)
			}
			pendingRef = ref
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NotifyHITL: %v", err)
	}
	return opRef, pendingRef
}

// The recorded ref has to be enough to delete the message later, and must
// carry no secrets — the runtime stores it, and api_url / number / auth are
// re-read from the secret store at delete time.
func TestSignalNotifyHITLRecordsNonSecretMessageRef(t *testing.T) {
	server, _, _ := signalDeleteServer(t, "1000000000000")
	withSignalClient(t, server.Client())

	opRef, pendingRef := signalNotifyCapturingRef(t, &SignalCLI{}, testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000", "auth": "u:p"}},
	})
	if opRef != pendingRef {
		t.Fatalf("operation ref %q != pending ref %q", opRef, pendingRef)
	}
	ref, ok := decodeSignalMessageRef(opRef)
	if !ok {
		t.Fatalf("ref does not decode: %q", opRef)
	}
	if ref.Credential != "signal-ops" || ref.Recipient != "+15551112222" || ref.TimestampMs != signalTestTimestamp {
		t.Fatalf("ref = %+v, want credential signal-ops, recipient +15551112222, ts %d", ref, signalTestTimestamp)
	}
	for _, secret := range []string{server.URL, "+15550000000", "u:p"} {
		if strings.Contains(opRef, secret) {
			t.Fatalf("ref %q leaks credential material %q", opRef, secret)
		}
	}
}

func TestSignalUpdateHITLMessageDeletesOnDecision(t *testing.T) {
	server, last, deleted := signalDeleteServer(t, "1000000000000")
	withSignalClient(t, server.Client())

	s := &SignalCLI{DeleteOnDecision: true}
	store := testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}
	_, ref := signalNotifyCapturingRef(t, s, store)

	err := s.UpdateHITLMessage(context.Background(), store, runtime.HITLMessageUpdate{
		MessageRef: ref,
		State:      runtime.HITLOperationStateDenied,
	})
	if err != nil {
		t.Fatalf("UpdateHITLMessage: %v", err)
	}
	if *deleted != 1 {
		t.Fatalf("remote-delete calls = %d, want 1", *deleted)
	}
	if last.Recipient != "+15551112222" {
		t.Fatalf("delete recipient = %q, want +15551112222", last.Recipient)
	}
	if last.Timestamp != signalTestTimestamp {
		t.Fatalf("delete timestamp = %d, want %d", last.Timestamp, signalTestTimestamp)
	}
}

// A prompt the operator is still expected to answer must survive: this is
// what the old wall-clock sweep got wrong.
func TestSignalUpdateHITLMessageKeepsUndecidedPrompt(t *testing.T) {
	server, _, deleted := signalDeleteServer(t, "1000000000000")
	withSignalClient(t, server.Client())

	s := &SignalCLI{DeleteOnDecision: true}
	store := testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}
	_, ref := signalNotifyCapturingRef(t, s, store)

	for _, state := range []runtime.HITLOperationState{
		runtime.HITLOperationStateSyncWaiting,
		runtime.HITLOperationStatePendingApproval,
	} {
		if err := s.UpdateHITLMessage(context.Background(), store, runtime.HITLMessageUpdate{MessageRef: ref, State: state}); err != nil {
			t.Fatalf("UpdateHITLMessage(%s): %v", state, err)
		}
	}
	if *deleted != 0 {
		t.Fatalf("remote-delete calls = %d, want 0 (prompt still awaiting a decision)", *deleted)
	}
}

func TestSignalUpdateHITLMessageOffByDefault(t *testing.T) {
	server, _, deleted := signalDeleteServer(t, "1000000000000")
	withSignalClient(t, server.Client())

	s := &SignalCLI{}
	store := testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}
	_, ref := signalNotifyCapturingRef(t, s, store)

	if err := s.UpdateHITLMessage(context.Background(), store, runtime.HITLMessageUpdate{
		MessageRef: ref,
		State:      runtime.HITLOperationStateDenied,
	}); err != nil {
		t.Fatalf("UpdateHITLMessage: %v", err)
	}
	if *deleted != 0 {
		t.Fatalf("remote-delete calls = %d, want 0 (delete_on_decision is off)", *deleted)
	}
}

// The same operation reaches several decided states in turn, so repeating the
// delete has to stay harmless rather than error out.
func TestSignalUpdateHITLMessageRepeatedDecisionsAreSafe(t *testing.T) {
	server, _, deleted := signalDeleteServer(t, "1000000000000")
	withSignalClient(t, server.Client())

	s := &SignalCLI{DeleteOnDecision: true}
	store := testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}
	_, ref := signalNotifyCapturingRef(t, s, store)

	for _, state := range []runtime.HITLOperationState{
		runtime.HITLOperationStateApprovedWaitingForRetry,
		runtime.HITLOperationStateExecutingUpstream,
		runtime.HITLOperationStateUpstreamSucceeded,
	} {
		if err := s.UpdateHITLMessage(context.Background(), store, runtime.HITLMessageUpdate{MessageRef: ref, State: state}); err != nil {
			t.Fatalf("UpdateHITLMessage(%s): %v", state, err)
		}
	}
	if *deleted != 3 {
		t.Fatalf("remote-delete calls = %d, want 3", *deleted)
	}
}

func TestSignalUpdateHITLMessageIgnoresForeignRef(t *testing.T) {
	server, _, deleted := signalDeleteServer(t, "1000000000000")
	withSignalClient(t, server.Client())

	s := &SignalCLI{DeleteOnDecision: true}
	store := testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}
	for _, raw := range []string{"", "not json", `{"type":"slack","credential":"signal-ops","channel":"C1","ts":"1.2"}`} {
		if err := s.UpdateHITLMessage(context.Background(), store, runtime.HITLMessageUpdate{
			MessageRef: raw,
			State:      runtime.HITLOperationStateDenied,
		}); err != nil {
			t.Fatalf("UpdateHITLMessage(%q): %v", raw, err)
		}
	}
	if *deleted != 0 {
		t.Fatalf("remote-delete calls = %d, want 0 (ref is not ours)", *deleted)
	}
}

func TestSignalHITLMessageRendersSummaryAndLink(t *testing.T) {
	msg := signalHITLMessage(runtime.ApproveRequest{
		Method:  "POST",
		Host:    "gitlab.com",
		Path:    "/api/v4/projects/1/issues",
		Profile: "uninfo",
	}, runtime.HITLTarget{
		PendingID:    "abc",
		DashboardURL: "https://gateway.example/",
		Summary: &runtime.HITLSummary{
			Subject:    "POST /api/v4/projects/1/issues",
			Label:      "write",
			Confidence: 90,
			Summary:    "creates an issue",
		},
	})
	for _, want := range []string{
		"clawpatrol:",
		"POST /api/v4/projects/1/issues",
		"Label: write (90%)",
		"Summary: creates an issue",
		"agent: uninfo",
		"https://gateway.example/#hitl/abc",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
}

func TestSignalNotifyHITLRejectsAuthWithoutColon(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000", "auth": "justatoken"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "+15551112222", PendingID: "p1"})
	if err == nil || !strings.Contains(err.Error(), "user:password") {
		t.Fatalf("err = %v, want auth-slot error", err)
	}
	if hits != 0 {
		t.Fatalf("request was sent unauthenticated (%d hits)", hits)
	}
}

func TestSignalNotifyHITLDoesNotFollowRedirects(t *testing.T) {
	elsewhereHits := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhereHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/v2/send", http.StatusFound)
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	err := (&SignalCLI{}).NotifyHITL(context.Background(), signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000", "auth": "u:p"}},
	}), runtime.HITLTarget{CredentialName: "signal-ops", Channel: "+15551112222", PendingID: "p1"})
	if err == nil {
		t.Fatal("a redirected send was reported as success")
	}
	if elsewhereHits != 0 {
		t.Fatalf("redirect was followed (%d hits on the other host)", elsewhereHits)
	}
}

func TestSignalHITLMessageOversizedBodyKeepsLink(t *testing.T) {
	var payload struct {
		Message string `json:"message"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	req := signalTestReq(testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	})
	req.BodySample = strings.Repeat("x", 20000)
	req.Reason = strings.Repeat("r", 5000)
	err := (&SignalCLI{}).NotifyHITL(context.Background(), req, runtime.HITLTarget{
		CredentialName: "signal-ops", Channel: "+15551112222", PendingID: "big-1", DashboardURL: "https://gateway.example",
	})
	if err != nil {
		t.Fatalf("NotifyHITL: %v", err)
	}
	if !strings.HasSuffix(strings.TrimSpace(payload.Message), "https://gateway.example/#hitl/big-1") {
		t.Fatalf("link not at the end of the message: ...%q", payload.Message[max(0, len(payload.Message)-120):])
	}
	if len(payload.Message) > 6000 {
		t.Fatalf("message not truncated: %d bytes", len(payload.Message))
	}
}

func TestSignalUpdateHITLMessageRetriesTransientDeleteFailure(t *testing.T) {
	deletes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/send":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"timestamp":"1000000000000"}`))
		case strings.HasPrefix(r.URL.Path, "/v1/remote-delete/"):
			deletes++
			if deletes == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	withSignalClient(t, server.Client())

	s := &SignalCLI{DeleteOnDecision: true}
	store := testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}
	_, ref := signalNotifyCapturingRef(t, s, store)
	if err := s.UpdateHITLMessage(context.Background(), store, runtime.HITLMessageUpdate{
		MessageRef: ref,
		State:      runtime.HITLOperationStateDenied,
	}); err != nil {
		t.Fatalf("UpdateHITLMessage: %v", err)
	}
	if deletes != 2 {
		t.Fatalf("remote-delete calls = %d, want 2 (one retry after 503)", deletes)
	}
}

// A sync approval (client still connected) is a decision too: the
// prompt must be deleted just like the async retry-grant approval.
func TestSignalUpdateHITLMessageDeletesOnSyncApproval(t *testing.T) {
	server, _, deleted := signalDeleteServer(t, "1000000000000")
	withSignalClient(t, server.Client())

	s := &SignalCLI{DeleteOnDecision: true}
	store := testSecretStore{
		"signal-ops": {Extras: map[string]string{"api_url": server.URL, "number": "+15550000000"}},
	}
	_, ref := signalNotifyCapturingRef(t, s, store)

	if err := s.UpdateHITLMessage(context.Background(), store, runtime.HITLMessageUpdate{
		MessageRef: ref,
		State:      runtime.HITLOperationStateApproved,
		DecidedBy:  "dashboard:alice",
	}); err != nil {
		t.Fatalf("UpdateHITLMessage: %v", err)
	}
	if *deleted != 1 {
		t.Fatalf("remote-delete calls = %d, want 1", *deleted)
	}
}
