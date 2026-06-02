package credentials

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestSlackNotifyHITLRecordsMessageRefForSyncPendingRequest(t *testing.T) {
	var recordedPendingID, recordedRef string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer xoxb-test" {
			t.Fatalf("Authorization header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1778764174.925659"}`))
	}))
	defer server.Close()

	oldURL := slackPostMessageURL
	oldClient := slackHTTPClient
	oldBackoff := slackNotifyRetryBackoff
	slackPostMessageURL = server.URL
	slackHTTPClient = server.Client()
	slackNotifyRetryBackoff = 0
	defer func() {
		slackPostMessageURL = oldURL
		slackHTTPClient = oldClient
		slackNotifyRetryBackoff = oldBackoff
	}()

	err := (&SlackTokens{}).NotifyHITL(context.Background(), runtime.ApproveRequest{
		Secrets: testSecretStore{
			"slack-approvals": {Extras: map[string]string{"bot": "xoxb-test"}},
		},
		Method: "POST",
		Host:   "api.example.test",
		Path:   "/v1/resources/update",
	}, runtime.HITLTarget{
		CredentialName: "slack-approvals",
		Channel:        "C123",
		PendingID:      "pending-123",
		Interactive:    true,
		PendingMessageUpdateSink: func(_ context.Context, pendingID, ref string) error {
			recordedPendingID = pendingID
			recordedRef = ref
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NotifyHITL returned error: %v", err)
	}
	if recordedPendingID != "pending-123" {
		t.Fatalf("recorded pending ID = %q", recordedPendingID)
	}
	ref, ok := decodeSlackMessageRef(recordedRef)
	if !ok {
		t.Fatalf("recorded ref did not decode: %q", recordedRef)
	}
	if ref.Credential != "slack-approvals" || ref.Channel != "C123" || ref.TS != "1778764174.925659" || ref.PendingID != "pending-123" || !ref.Interactive {
		t.Fatalf("recorded ref = %#v", ref)
	}
}

func TestSlackNotifyHITLRecordsMessageRefForAsyncOperation(t *testing.T) {
	var recordedOperationID, recordedRef string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer xoxb-test" {
			t.Fatalf("Authorization header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1778764174.925659"}`))
	}))
	defer server.Close()

	oldURL := slackPostMessageURL
	oldClient := slackHTTPClient
	oldBackoff := slackNotifyRetryBackoff
	slackPostMessageURL = server.URL
	slackHTTPClient = server.Client()
	slackNotifyRetryBackoff = 0
	defer func() {
		slackPostMessageURL = oldURL
		slackHTTPClient = oldClient
		slackNotifyRetryBackoff = oldBackoff
	}()

	err := (&SlackTokens{}).NotifyHITL(context.Background(), runtime.ApproveRequest{
		Secrets: testSecretStore{
			"slack-approvals": {Extras: map[string]string{"bot": "xoxb-test"}},
		},
		AsyncOperationID: "op-123",
		Method:           "POST",
		Host:             "api.example.test",
		Path:             "/v1/resources/update",
	}, runtime.HITLTarget{
		CredentialName: "slack-approvals",
		Channel:        "C123",
		PendingID:      "pending-123",
		Interactive:    true,
		MessageUpdateSink: func(_ context.Context, operationID, ref string) error {
			recordedOperationID = operationID
			recordedRef = ref
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NotifyHITL returned error: %v", err)
	}
	if recordedOperationID != "op-123" {
		t.Fatalf("recorded operation ID = %q", recordedOperationID)
	}
	ref, ok := decodeSlackMessageRef(recordedRef)
	if !ok {
		t.Fatalf("recorded ref did not decode: %q", recordedRef)
	}
	if ref.Credential != "slack-approvals" || ref.Channel != "C123" || ref.TS != "1778764174.925659" || ref.PendingID != "pending-123" || !ref.Interactive {
		t.Fatalf("recorded ref = %#v", ref)
	}
}

func TestSlackNotifyHITLRecordsMessageOverrideForUpdates(t *testing.T) {
	var recordedRef string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1778764174.925659"}`))
	}))
	defer server.Close()

	oldURL := slackPostMessageURL
	oldClient := slackHTTPClient
	oldBackoff := slackNotifyRetryBackoff
	slackPostMessageURL = server.URL
	slackHTTPClient = server.Client()
	slackNotifyRetryBackoff = 0
	defer func() {
		slackPostMessageURL = oldURL
		slackHTTPClient = oldClient
		slackNotifyRetryBackoff = oldBackoff
	}()

	customMessage := "deploying to prod, contact @oncall"
	err := (&SlackTokens{}).NotifyHITL(context.Background(), runtime.ApproveRequest{
		Secrets:          testSecretStore{"slack-approvals": {Extras: map[string]string{"bot": "xoxb-test"}}},
		AsyncOperationID: "op-123",
		Method:           "POST",
		Host:             "api.example.test",
		Path:             "/v1/resources/update",
	}, runtime.HITLTarget{
		CredentialName: "slack-approvals",
		Channel:        "C123",
		PendingID:      "pending-123",
		Interactive:    true,
		Message:        customMessage,
		MessageUpdateSink: func(_ context.Context, _, ref string) error {
			recordedRef = ref
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NotifyHITL returned error: %v", err)
	}
	ref, ok := decodeSlackMessageRef(recordedRef)
	if !ok {
		t.Fatalf("recorded ref did not decode: %q", recordedRef)
	}
	blocks := slackHITLUpdateBlocks(runtime.HITLMessageUpdate{
		State:  runtime.HITLOperationStateApprovedWaitingForRetry,
		Method: "POST",
		Host:   "api.example.test",
		Path:   "/v1/resources/update",
	}, ref)
	buf, _ := json.Marshal(blocks)
	if !strings.Contains(string(buf), customMessage) {
		t.Fatalf("updated blocks lost custom message override: %s", buf)
	}
}

func TestSlackUpdateHITLMessageUsesChatUpdate(t *testing.T) {
	var body struct {
		Channel string           `json:"channel"`
		TS      string           `json:"ts"`
		Text    string           `json:"text"`
		Blocks  []map[string]any `json:"blocks"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer xoxb-test" {
			t.Fatalf("Authorization header = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode chat.update payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	oldURL := slackUpdateMessageURL
	oldClient := slackHTTPClient
	slackUpdateMessageURL = server.URL
	slackHTTPClient = server.Client()
	defer func() {
		slackUpdateMessageURL = oldURL
		slackHTTPClient = oldClient
	}()

	ref := encodeSlackMessageRef(slackMessageRef{Credential: "slack-approvals", Channel: "C123", TS: "1778764174.925659", PendingID: "pending-123", Interactive: true})
	err := (&SlackTokens{}).UpdateHITLMessage(context.Background(), testSecretStore{
		"slack-approvals": {Extras: map[string]string{"bot": "xoxb-test"}},
	}, runtime.HITLMessageUpdate{
		MessageRef:     ref,
		OperationID:    "op-123",
		State:          runtime.HITLOperationStateUpstreamSucceeded,
		Method:         "POST",
		Host:           "api.example.test",
		Path:           "/v1/resources/update",
		UpstreamCalled: true,
	})
	if err != nil {
		t.Fatalf("UpdateHITLMessage returned error: %v", err)
	}
	if body.Channel != "C123" || body.TS != "1778764174.925659" {
		t.Fatalf("chat.update target = %q/%q", body.Channel, body.TS)
	}
	buf, _ := json.Marshal(body.Blocks)
	text := string(buf)
	if !strings.Contains(text, "Upstream request succeeded") {
		t.Fatalf("chat.update blocks = %s, want upstream success status", text)
	}
	if strings.Contains(text, "action_id") {
		t.Fatalf("terminal chat.update should not keep action buttons: %s", text)
	}
}

func TestSlackUpdateHITLMessageRetriesTransientChatUpdateFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error":"ratelimited"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	oldURL := slackUpdateMessageURL
	oldClient := slackHTTPClient
	oldBackoff := slackNotifyRetryBackoff
	slackUpdateMessageURL = server.URL
	slackHTTPClient = server.Client()
	slackNotifyRetryBackoff = 0
	defer func() {
		slackUpdateMessageURL = oldURL
		slackHTTPClient = oldClient
		slackNotifyRetryBackoff = oldBackoff
	}()

	ref := encodeSlackMessageRef(slackMessageRef{Credential: "slack-approvals", Channel: "C123", TS: "1778764174.925659"})
	err := (&SlackTokens{}).UpdateHITLMessage(context.Background(), testSecretStore{
		"slack-approvals": {Extras: map[string]string{"bot": "xoxb-test"}},
	}, runtime.HITLMessageUpdate{
		MessageRef: ref,
		State:      runtime.HITLOperationStateUpstreamSucceeded,
		Method:     "POST",
		Host:       "api.example.test",
		Path:       "/v1/resources/update",
	})
	if err != nil {
		t.Fatalf("UpdateHITLMessage returned error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("chat.update attempts = %d, want retry after transient failure", attempts)
	}
}

func TestSlackUpdateHITLMessageClientDisconnectedCopyMatchesSyncHITL(t *testing.T) {
	blocks := slackHITLUpdateBlocks(runtime.HITLMessageUpdate{
		State:          runtime.HITLOperationStateClientDisconnected,
		Method:         "POST",
		Host:           "api.example.test",
		Path:           "/v1/resources/update",
		UpstreamCalled: false,
	}, slackMessageRef{Credential: "slack-approvals", Channel: "C123", TS: "1778764174.925659"})
	buf, _ := json.Marshal(blocks)
	text := string(buf)
	if !strings.Contains(text, "Original client disconnected before approval") || !strings.Contains(text, "upstream request was not sent") {
		t.Fatalf("client-disconnected update blocks = %s, want sync HITL upstream-not-sent copy", text)
	}
	if strings.Contains(text, "async polling handle") {
		t.Fatalf("client-disconnected update kept async-only wording: %s", text)
	}
}

func TestSlackUpdateHITLMessageRedactsSensitiveLastError(t *testing.T) {
	blocks := slackHITLUpdateBlocks(runtime.HITLMessageUpdate{
		State:     runtime.HITLOperationStateUpstreamFailed,
		Method:    "POST",
		Host:      "api.example.test",
		Path:      "/v1/resources/update",
		LastError: "upstream 500: https://api.example.test/v1/resources/update?api_key=sk-live-secret&ok=1 https://hooks.slack.com/services/T000/B000/path-secret Authorization: Bearer xoxb-real-token X-Api-Key: abc123",
	}, slackMessageRef{Credential: "slack-approvals", Channel: "C123", TS: "1778764174.925659"})
	buf, _ := json.Marshal(blocks)
	text := string(buf)
	for _, leaked := range []string{"sk-live-secret", "xoxb-real-token", "abc123", "path-secret"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("updated blocks leaked sensitive LastError value %q: %s", leaked, text)
		}
	}
	if !strings.Contains(text, "api_key=[redacted]") || !strings.Contains(text, "Authorization: [redacted]") || !strings.Contains(text, "X-Api-Key: [redacted]") {
		t.Fatalf("updated blocks did not show redacted placeholders: %s", text)
	}
}

func TestSlackUpdateHITLMessageDoesNotAddButtonsForNonInteractivePrompt(t *testing.T) {
	blocks := slackHITLUpdateBlocks(runtime.HITLMessageUpdate{
		State:  runtime.HITLOperationStatePendingApproval,
		Method: "POST",
		Host:   "api.example.test",
		Path:   "/v1/resources/update",
	}, slackMessageRef{
		Credential:  "slack-approvals",
		Channel:     "C123",
		TS:          "1778764174.925659",
		PendingID:   "pending-123",
		Interactive: false,
	})
	buf, _ := json.Marshal(blocks)
	text := string(buf)
	if strings.Contains(text, "action_id") || strings.Contains(text, "pending-123") {
		t.Fatalf("non-interactive update should not introduce Slack buttons: %s", text)
	}
}
