package middlewares

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rewrite is a test helper: it builds a POST /v1/messages request with
// the given JSON body, runs the middleware, and returns the decoded
// result object.
func rewrite(t *testing.T, m *AnthropicSystemPrompt, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	out, err := m.RewriteHTTPRequest(context.Background(), req, []byte(body))
	if err != nil {
		t.Fatalf("RewriteHTTPRequest: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("result not JSON: %v (%s)", err, out)
	}
	return obj
}

// TestAppendSystemAbsent: a request with no `system` field gets the
// injected text as a bare string.
func TestAppendSystemAbsent(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "TOOLS: gateway"}
	obj := rewrite(t, m, `{"model":"claude","messages":[]}`)
	sys, ok := obj["system"].(string)
	if !ok {
		t.Fatalf("system is %T, want string", obj["system"])
	}
	if sys != "TOOLS: gateway" {
		t.Errorf("system = %q, want injected text", sys)
	}
	// Other fields preserved.
	if obj["model"] != "claude" {
		t.Errorf("model field lost: %v", obj["model"])
	}
}

// TestAppendSystemString: a string `system` gets the injected text
// appended after a blank-line separator.
func TestAppendSystemString(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "TOOLS: gateway"}
	obj := rewrite(t, m, `{"system":"You are helpful.","messages":[]}`)
	sys, ok := obj["system"].(string)
	if !ok {
		t.Fatalf("system is %T, want string", obj["system"])
	}
	if sys != "You are helpful.\n\nTOOLS: gateway" {
		t.Errorf("system = %q, want original + injected", sys)
	}
}

// TestAppendSystemArray: a content-block array `system` gets a new
// text block appended at the end; existing blocks are untouched.
func TestAppendSystemArray(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "TOOLS: gateway"}
	obj := rewrite(t, m, `{"system":[{"type":"text","text":"base","cache_control":{"type":"ephemeral"}}],"messages":[]}`)
	arr, ok := obj["system"].([]any)
	if !ok {
		t.Fatalf("system is %T, want array", obj["system"])
	}
	if len(arr) != 2 {
		t.Fatalf("system array len = %d, want 2", len(arr))
	}
	// First block preserved verbatim (including cache_control).
	first := arr[0].(map[string]any)
	if first["text"] != "base" {
		t.Errorf("first block text = %v, want base", first["text"])
	}
	if first["cache_control"] == nil {
		t.Errorf("first block lost cache_control")
	}
	// Second block is the injected text.
	second := arr[1].(map[string]any)
	if second["type"] != "text" || second["text"] != "TOOLS: gateway" {
		t.Errorf("appended block = %v, want {type:text, text:injected}", second)
	}
}

// TestNonMessagesPassThrough: a request to a different path is returned
// byte-for-byte unchanged.
func TestNonMessagesPassThrough(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "TOOLS"}
	body := `{"system":"x"}`
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/complete", strings.NewReader(body))
	out, err := m.RewriteHTTPRequest(context.Background(), req, []byte(body))
	if err != nil {
		t.Fatalf("RewriteHTTPRequest: %v", err)
	}
	if string(out) != body {
		t.Errorf("non-Messages body mutated: %s", out)
	}
}

// TestGetPassThrough: a GET (no body transform) passes through.
func TestGetPassThrough(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "TOOLS"}
	req := httptest.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/messages", nil)
	out, err := m.RewriteHTTPRequest(context.Background(), req, []byte(nil))
	if err != nil {
		t.Fatalf("RewriteHTTPRequest: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("GET body should stay empty, got %s", out)
	}
}

// TestFailClosedBadShape: a `system` field in an unrecognized shape
// (number) fails the request closed rather than silently passing it
// upstream without the injection.
func TestFailClosedBadShape(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "TOOLS"}
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(`{"system":42}`))
	_, err := m.RewriteHTTPRequest(context.Background(), req, []byte(`{"system":42}`))
	if err == nil {
		t.Fatal("expected error on numeric system shape, got nil")
	}
}

// TestFailClosedBadJSON: a body that isn't a JSON object fails closed.
func TestFailClosedBadJSON(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "TOOLS"}
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(`not json`))
	_, err := m.RewriteHTTPRequest(context.Background(), req, []byte(`not json`))
	if err == nil {
		t.Fatal("expected error on non-JSON body, got nil")
	}
}

// TestEmptyTextPassThrough: an empty Text is a no-op even on a
// Messages request (defensive — the loader requires text, but a
// zero-value instance shouldn't mangle bodies).
func TestEmptyTextPassThrough(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: ""}
	body := `{"system":"x","messages":[]}`
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	out, err := m.RewriteHTTPRequest(context.Background(), req, []byte(body))
	if err != nil {
		t.Fatalf("RewriteHTTPRequest: %v", err)
	}
	if string(out) != body {
		t.Errorf("empty-text body mutated: %s", out)
	}
}

// TestCheckEndpointHosts: the host-family compatibility check accepts
// endpoints that intercept api.anthropic.com (with or without a port)
// and rejects others.
func TestCheckEndpointHosts(t *testing.T) {
	m := &AnthropicSystemPrompt{Text: "x"}
	cases := []struct {
		hosts []string
		ok    bool
	}{
		{[]string{"api.anthropic.com"}, true},
		{[]string{"api.anthropic.com:443"}, true},
		{[]string{"other.com", "API.ANTHROPIC.COM"}, true}, // case-insensitive
		{[]string{"api.openai.com"}, false},
		{nil, false},
	}
	for _, c := range cases {
		err := m.CheckEndpointHosts(c.hosts)
		if (err == nil) != c.ok {
			t.Errorf("CheckEndpointHosts(%v) err=%v, want ok=%v", c.hosts, err, c.ok)
		}
	}
}
