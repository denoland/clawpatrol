package middlewares

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// newMessagesReq builds a POST /v1/messages request for the middleware
// under test. Path/method gating is what the middleware keys on; the
// body is supplied separately to RewriteHTTPRequest.
func newMessagesReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func TestAnthropicSystemPromptShapes(t *testing.T) {
	const inject = "TOOL DISCOVERY"
	mw := &AnthropicSystemPrompt{Text: inject}

	cases := []struct {
		name string
		in   string
		// check inspects the decoded `system` field of the rewritten body.
		check func(t *testing.T, system json.RawMessage)
	}{
		{
			name: "absent",
			in:   `{"model":"claude","messages":[]}`,
			check: func(t *testing.T, sys json.RawMessage) {
				var s string
				if err := json.Unmarshal(sys, &s); err != nil {
					t.Fatalf("system not a string: %v (%s)", err, sys)
				}
				if s != inject {
					t.Errorf("system = %q, want %q", s, inject)
				}
			},
		},
		{
			name: "string",
			in:   `{"model":"claude","system":"BASE","messages":[]}`,
			check: func(t *testing.T, sys json.RawMessage) {
				var s string
				if err := json.Unmarshal(sys, &s); err != nil {
					t.Fatalf("system not a string: %v (%s)", err, sys)
				}
				if want := "BASE\n\n" + inject; s != want {
					t.Errorf("system = %q, want %q", s, want)
				}
			},
		},
		{
			name: "array",
			in:   `{"model":"claude","system":[{"type":"text","text":"BASE"}],"messages":[]}`,
			check: func(t *testing.T, sys json.RawMessage) {
				var blocks []map[string]any
				if err := json.Unmarshal(sys, &blocks); err != nil {
					t.Fatalf("system not an array: %v (%s)", err, sys)
				}
				if len(blocks) != 2 {
					t.Fatalf("expected 2 blocks, got %d (%s)", len(blocks), sys)
				}
				last := blocks[1]
				if last["type"] != "text" || last["text"] != inject {
					t.Errorf("appended block = %v, want {type:text,text:%q}", last, inject)
				}
				// First block preserved.
				if blocks[0]["text"] != "BASE" {
					t.Errorf("original block mutated: %v", blocks[0])
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := mw.RewriteHTTPRequest(context.Background(), newMessagesReq(t), []byte(c.in))
			if err != nil {
				t.Fatalf("RewriteHTTPRequest: %v", err)
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(out, &payload); err != nil {
				t.Fatalf("rewritten body not JSON: %v (%s)", err, out)
			}
			c.check(t, payload["system"])
		})
	}
}

// TestAnthropicSystemPromptPassthrough verifies non-applicable requests
// and the empty-text no-op leave the body byte-for-byte unchanged.
func TestAnthropicSystemPromptPassthrough(t *testing.T) {
	body := []byte(`{"model":"claude","system":"BASE","messages":[]}`)

	t.Run("wrong path", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/complete", nil)
		out, err := (&AnthropicSystemPrompt{Text: "X"}).RewriteHTTPRequest(context.Background(), req, body)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("body mutated on wrong path: %s", out)
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/messages", nil)
		out, err := (&AnthropicSystemPrompt{Text: "X"}).RewriteHTTPRequest(context.Background(), req, body)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("body mutated on GET: %s", out)
		}
	})

	t.Run("empty text", func(t *testing.T) {
		out, err := (&AnthropicSystemPrompt{Text: ""}).RewriteHTTPRequest(context.Background(), newMessagesReq(t), body)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("empty-text middleware mutated body: %s", out)
		}
	})
}

// TestAnthropicSystemPromptFailClosed verifies a malformed body (and a
// non-object/array/string `system` shape) surfaces an error so the
// dispatcher can fail the request closed.
func TestAnthropicSystemPromptFailClosed(t *testing.T) {
	mw := &AnthropicSystemPrompt{Text: "X"}
	for _, in := range []string{
		`not json`,
		`{"model":"claude","system":42,"messages":[]}`,
	} {
		out, err := mw.RewriteHTTPRequest(context.Background(), newMessagesReq(t), []byte(in))
		if err == nil {
			t.Errorf("expected error for body %q, got out=%s", in, out)
		}
		if out != nil {
			t.Errorf("expected nil body on error for %q, got %s", in, out)
		}
	}
}

func TestAnthropicSystemPromptCheckEndpointHosts(t *testing.T) {
	mw := &AnthropicSystemPrompt{Text: "X"}
	ok := [][]string{
		{"api.anthropic.com"},
		{"api.anthropic.com:443"},
		{"other.example.com", "API.ANTHROPIC.COM"},
	}
	for _, hosts := range ok {
		if err := mw.CheckEndpointHosts(hosts); err != nil {
			t.Errorf("CheckEndpointHosts(%v) = %v, want nil", hosts, err)
		}
	}
	bad := [][]string{
		{"api.openai.com"},
		{"example.com:443"},
		nil,
	}
	for _, hosts := range bad {
		if err := mw.CheckEndpointHosts(hosts); err == nil {
			t.Errorf("CheckEndpointHosts(%v) = nil, want error", hosts)
		}
	}
}

// TestAnthropicSystemPromptFileInclude confirms the Text field opts into
// <<file:NAME>> inlining.
func TestAnthropicSystemPromptFileInclude(t *testing.T) {
	mw := &AnthropicSystemPrompt{Text: "<<file:x>>"}
	fields := mw.FileIncludeFields()
	if len(fields) != 1 {
		t.Fatalf("expected 1 file-include field, got %d", len(fields))
	}
	if got := fields[0].Get(); got != "<<file:x>>" {
		t.Errorf("Get() = %q", got)
	}
	fields[0].Set("resolved")
	if mw.Text != "resolved" {
		t.Errorf("Set did not update Text: %q", mw.Text)
	}
}
