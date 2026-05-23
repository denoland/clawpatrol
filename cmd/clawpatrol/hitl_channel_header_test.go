package main

import "testing"

// sanitizeSlackChannelHeader gates the X-HITL-Channel header before
// it's threaded into the approver request. The header is
// agent-controlled, so anything that doesn't shape like a Slack
// channel ID must be dropped — otherwise an attacker-shaped value
// could land in chat.postMessage verbatim.
func TestSanitizeSlackChannelHeader(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Public + private channels accepted.
		{"C0AH1SJGHAP", "C0AH1SJGHAP"},
		{"C03P8NG2Q06", "C03P8NG2Q06"},
		{"GABC12345", "GABC12345"}, // private channel / mpim
		// Whitespace trimmed.
		{"  C0AH1SJGHAP  ", "C0AH1SJGHAP"},

		// Empty in, empty out — caller falls back to static block field.
		{"", ""},

		// DMs and user IDs rejected — not valid HITL destinations.
		{"D12345678", ""},
		{"U12345678", ""},

		// Too short / too long.
		{"C123", ""},
		{"C" + repeat("A", 25), ""},

		// Wrong shape — lowercase, punctuation, injection attempts.
		{"c0ah1sjghap", ""},
		{"C0AH1S JGHAP", ""},
		{"C0AH1S\nJGHAP", ""},
		{"C0AH1S;DROP", ""},
		{"<a>C0AH1SJGHAP", ""},
	}
	for _, c := range cases {
		got := sanitizeSlackChannelHeader(c.in)
		if got != c.want {
			t.Errorf("sanitizeSlackChannelHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
