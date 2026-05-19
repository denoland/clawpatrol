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
