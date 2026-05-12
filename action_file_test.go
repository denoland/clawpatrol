package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestFixtureUnmarshalAcceptsMissingEndpoint(t *testing.T) {
	body := `{"match":{"verdict":"allow"},"action":{"host":"api.github.com","http":{"method":"GET","path":"/user"}}}`
	var f Fixture
	if err := json.Unmarshal([]byte(body), &f); err != nil {
		t.Fatalf("endpoint should be optional, got %v", err)
	}
	if f.Match.Endpoint != "" {
		t.Fatalf("expected empty match.endpoint, got %q", f.Match.Endpoint)
	}
}

// passthrough is a valid verdict at parse time; the runner rejects it
// at replay (see test.go) but the fixture format accepts it so old
// exports don't fail to load.
func TestFixtureUnmarshalAcceptsPassthrough(t *testing.T) {
	body := `{"match":{"verdict":"passthrough"},"action":{"host":"x","http":{}}}`
	var f Fixture
	if err := json.Unmarshal([]byte(body), &f); err != nil {
		t.Fatalf("passthrough should parse, got %v", err)
	}
	if f.Match.Verdict != "passthrough" {
		t.Fatalf("verdict=%q want passthrough", f.Match.Verdict)
	}
}

func TestFixtureUnmarshalRejections(t *testing.T) {
	cases := []struct {
		name, body, wantSubstr string
	}{
		{"zero families",
			`{"match":{"verdict":"allow"},"action":{"host":"x"}}`,
			"exactly one of http/k8s/sql"},
		{"two families",
			`{"match":{"verdict":"allow"},"action":{"host":"x","http":{},"sql":{"statement":"select 1"}}}`,
			"exactly one of http/k8s/sql"},
		{"unknown key in family",
			`{"match":{"verdict":"allow"},"action":{"host":"x","http":{"banana":1}}}`,
			"banana"},
		{"unknown top-level key",
			`{"match":{"verdict":"allow"},"action":{"host":"x","http":{}},"novel":1}`,
			"novel"},
		{"unknown key in action",
			`{"match":{"verdict":"allow"},"action":{"host":"x","http":{},"novel":1}}`,
			"novel"},
		{"body and body_b64 both set",
			`{"match":{"verdict":"allow"},"action":{"host":"x","http":{"body":"hi","body_b64":"aGk="}}}`,
			"mutually exclusive"},
		{"sql without statement",
			`{"match":{"verdict":"allow"},"action":{"host":"x","sql":{}}}`,
			"statement is required"},
		{"bad match.verdict",
			`{"match":{"verdict":"maybe"},"action":{"host":"x","http":{}}}`,
			"match.verdict"},
		{"missing match",
			`{"action":{"host":"x","http":{}}}`,
			"match is required"},
		{"missing action",
			`{"match":{"verdict":"allow"}}`,
			"action is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var f Fixture
			err := json.Unmarshal([]byte(tc.body), &f)
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("err=%v, want substring %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestMatchFromCompiledRule(t *testing.T) {
	ep := &config.CompiledEndpoint{Name: "ep"}
	cases := []struct {
		name string
		cr   *config.CompiledRule
		want Match
	}{
		{"nil-rule", nil, Match{Verdict: "allow", Endpoint: "ep"}},
		{"explicit-allow",
			&config.CompiledRule{Name: "r1", Outcome: config.Outcome{Verdict: "allow"}},
			Match{Verdict: "allow", Rule: "r1", Endpoint: "ep"}},
		{"deny",
			&config.CompiledRule{Name: "r2", Outcome: config.Outcome{Verdict: "deny", Reason: "no"}},
			Match{Verdict: "deny", Rule: "r2", Endpoint: "ep", Reason: "no"}},
		{"approve-chain",
			&config.CompiledRule{Name: "r3", Outcome: config.Outcome{Approve: []config.ApproveStage{{}}}},
			Match{Verdict: "approve", Rule: "r3", Endpoint: "ep"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchFromCompiledRule(tc.cr, ep)
			if got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestEncodeBodyRoundTrip(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("hello world"),
		[]byte("{\n  \"k\": 1\n}"),
		{0x00, 0x01, 0x02, 0xff},
	} {
		body, b64 := encodeBody(in)
		out, err := decodedBody(body, b64)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if string(out) != string(in) {
			t.Fatalf("round-trip mismatch: in=%q out=%q (body=%q b64=%q)", in, out, body, b64)
		}
	}
}
