package credentials

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type testSecretStore map[string]runtime.Secret

func (s testSecretStore) Get(name string) (runtime.Secret, error) {
	return s[name], nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSlackNotifyHITLRetriesTransientPostMessageFailure(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, `{"ok":false,"error":"temporary_failure"}`, http.StatusBadGateway)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer xoxb-test" {
			t.Fatalf("Authorization header = %q", got)
		}
		var body struct {
			Channel  string `json:"channel"`
			ThreadTS string `json:"thread_ts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode Slack payload: %v", err)
		}
		if body.Channel != "C123" || body.ThreadTS != "1778764174.925659" {
			t.Fatalf("payload channel/thread = %q/%q", body.Channel, body.ThreadTS)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
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
			"slack-dev": {Extras: map[string]string{"bot": "xoxb-test"}},
		},
		Method: "POST",
		Host:   "console.example.com",
		Path:   "/v1/resources/archive",
	}, runtime.HITLTarget{
		CredentialName: "slack-dev",
		Channel:        "C123",
		ThreadTS:       "1778764174.925659",
		PendingID:      "pending-123",
		Interactive:    true,
	})
	if err != nil {
		t.Fatalf("NotifyHITL returned error after retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestSlackNotifyHITLRetriesOnceAfterTransportTimeout(t *testing.T) {
	var attempts int
	oldURL := slackPostMessageURL
	oldClient := slackHTTPClient
	oldBackoff := slackNotifyRetryBackoff
	slackPostMessageURL = "https://slack.test/api/chat.postMessage"
	slackHTTPClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, context.DeadlineExceeded
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		}, nil
	})}
	slackNotifyRetryBackoff = 0
	defer func() {
		slackPostMessageURL = oldURL
		slackHTTPClient = oldClient
		slackNotifyRetryBackoff = oldBackoff
	}()

	err := (&SlackTokens{}).NotifyHITL(context.Background(), runtime.ApproveRequest{
		Secrets: testSecretStore{
			"slack-dev": {Extras: map[string]string{"bot": "xoxb-test"}},
		},
		Method: "POST",
		Host:   "console.example.com",
		Path:   "/v1/resources/archive",
	}, runtime.HITLTarget{
		CredentialName: "slack-dev",
		Channel:        "C123",
		PendingID:      "pending-123",
		Interactive:    true,
	})
	if err != nil {
		t.Fatalf("NotifyHITL returned error after retrying timeout: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestSlackNotifyHITLExplainsAsyncRetryGrantApproval(t *testing.T) {
	var body struct {
		Blocks []map[string]any `json:"blocks"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode Slack payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
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
			"slack-dev": {Extras: map[string]string{"bot": "xoxb-test"}},
		},
		Method: "POST",
		Host:   "console.example.com",
		Path:   "/v1/resources/archive",
	}, runtime.HITLTarget{
		CredentialName: "slack-dev",
		Channel:        "C123",
		PendingID:      "pending-123",
		Interactive:    true,
		OperationState: runtime.HITLOperationStatePendingApproval,
		ApprovalEffect: runtime.HITLApprovalEffectCreateRetryGrant,
		UpstreamCalled: false,
	})
	if err != nil {
		t.Fatalf("NotifyHITL returned error: %v", err)
	}

	buf, err := json.Marshal(body.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	text := string(buf)
	for _, want := range []string{
		"Upstream has not been called",
		"Approve will not send the request upstream now",
		"Approve will allow the client to retry the same request once",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Slack blocks = %s, want substring %q", text, want)
		}
	}
	if strings.Contains(text, "send this request upstream immediately") {
		t.Fatalf("Slack blocks used sync-waiting copy for async retry grant: %s", text)
	}
}

func TestSlackHITLContentBlocksRenderGenericSummary(t *testing.T) {
	blocks := slackHITLContentBlocks(
		"Approve POST · api.example.test",
		"Path",
		"/v1/messages",
		"",
		&runtime.HITLSummary{
			Subject:    "POST /v1/messages",
			Label:      "Needs review",
			Confidence: 82,
			Summary:    "Message changes customer-visible copy.",
		},
	)

	buf, err := json.Marshal(blocks)
	if err != nil {
		t.Fatal(err)
	}
	text := string(buf)
	for _, want := range []string{
		"POST /v1/messages",
		"*Label:* Needs review (82%)",
		"*Summary:* Message changes customer-visible copy.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Slack blocks = %s, want substring %q", text, want)
		}
	}
	for _, forbidden := range []string{"Class" + "ification", "ticket" + "_id", "Sp" + "am", "Leg" + "it"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Slack blocks contain coupled term %q: %s", forbidden, text)
		}
	}
}

func TestSlackNotifyHITLDoesNotRetryNonTransientSlackError(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
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
			"slack-dev": {Extras: map[string]string{"bot": "xoxb-test"}},
		},
		Method: "POST",
		Host:   "console.example.com",
		Path:   "/v1/resources/archive",
	}, runtime.HITLTarget{
		CredentialName: "slack-dev",
		Channel:        "missing-channel",
		PendingID:      "pending-123",
		Interactive:    true,
	})
	if err == nil {
		t.Fatalf("NotifyHITL error = nil, want Slack error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}
