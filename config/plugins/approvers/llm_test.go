package approvers

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/denoland/clawpatrol/config/runtime"
)

func TestBodyLimitDefault(t *testing.T) {
	a := &LLMApprover{}
	if got := a.bodyLimit(); got != defaultLLMBodyLimit {
		t.Fatalf("unset llm_body_limit: got %d, want %d", got, defaultLLMBodyLimit)
	}
}

func TestBodyLimitZeroSentinel(t *testing.T) {
	zero := 0
	a := &LLMApprover{LLMBodyLimit: &zero}
	if got := a.bodyLimit(); got != 0 {
		t.Fatalf("llm_body_limit=0: got %d, want 0", got)
	}
}

func TestBodyLimitExplicit(t *testing.T) {
	n := 256
	a := &LLMApprover{LLMBodyLimit: &n}
	if got := a.bodyLimit(); got != 256 {
		t.Fatalf("llm_body_limit=256: got %d, want 256", got)
	}
}

func TestTruncateBody(t *testing.T) {
	long := strings.Repeat("x", 100)

	cases := []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{"no truncation when zero limit", long, 0, long},
		{"no truncation when negative limit", long, -1, long},
		{"no truncation when input fits", "abc", 10, "abc"},
		{"truncation when input exceeds", long, 10, strings.Repeat("x", 10) + "…"},
		{"leading whitespace trimmed", "   abc", 10, "abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := truncateBody(c.in, c.limit); got != c.want {
				t.Fatalf("truncateBody(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
			}
		})
	}
}

// TestLLMBodyLimitHCLDecode confirms that gohcl distinguishes
// "attribute omitted" from "attribute set to 0" for the pointer-int
// field, which is the contract that makes the zero sentinel work.
func TestLLMBodyLimitHCLDecode(t *testing.T) {
	cases := []struct {
		name string
		hcl  string
		want *int
	}{
		{
			name: "unset",
			hcl:  `model = "claude-haiku-4-5-20251001"` + "\n" + `credential = "cred"`,
			want: nil,
		},
		{
			name: "explicit zero",
			hcl:  `model = "claude-haiku-4-5-20251001"` + "\n" + `credential = "cred"` + "\n" + `llm_body_limit = 0`,
			want: intPtr(0),
		},
		{
			name: "positive value",
			hcl:  `model = "claude-haiku-4-5-20251001"` + "\n" + `credential = "cred"` + "\n" + `llm_body_limit = 8192`,
			want: intPtr(8192),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, diags := hclsyntax.ParseConfig([]byte(c.hcl), "test.hcl", hcl.Pos{Line: 1, Column: 1})
			if diags.HasErrors() {
				t.Fatalf("parse: %v", diags)
			}
			var a LLMApprover
			diags = gohcl.DecodeBody(f.Body, nil, &a)
			if diags.HasErrors() {
				t.Fatalf("decode: %v", diags)
			}
			switch {
			case c.want == nil && a.LLMBodyLimit != nil:
				t.Fatalf("expected nil, got %d", *a.LLMBodyLimit)
			case c.want != nil && a.LLMBodyLimit == nil:
				t.Fatalf("expected %d, got nil", *c.want)
			case c.want != nil && *a.LLMBodyLimit != *c.want:
				t.Fatalf("expected %d, got %d", *c.want, *a.LLMBodyLimit)
			}
		})
	}
}

func intPtr(n int) *int { return &n }

func TestBuildJudgePromptRespectsBodyLimit(t *testing.T) {
	// Use a distinctive marker character that won't appear in the
	// surrounding prompt scaffolding, so a simple count isolates the
	// embedded body bytes.
	body := strings.Repeat("Z", 5000)
	req := runtime.ApproveRequest{
		Method:     "POST",
		Host:       "host",
		Path:       "/p",
		BodySample: body,
	}

	t.Run("default limit truncates", func(t *testing.T) {
		got := buildJudgePrompt(req, "policy", defaultLLMBodyLimit)
		if !strings.Contains(got, "…") {
			t.Fatalf("expected ellipsis marking truncation, got prompt:\n%s", got)
		}
		if strings.Count(got, "Z") != defaultLLMBodyLimit {
			t.Fatalf("expected exactly %d body bytes after truncation, got %d",
				defaultLLMBodyLimit, strings.Count(got, "Z"))
		}
	})

	t.Run("zero limit sends full body", func(t *testing.T) {
		got := buildJudgePrompt(req, "policy", 0)
		if strings.Contains(got, "…") {
			t.Fatalf("expected no ellipsis when limit=0, got prompt:\n%s", got)
		}
		if strings.Count(got, "Z") != len(body) {
			t.Fatalf("expected full body of %d bytes, got %d",
				len(body), strings.Count(got, "Z"))
		}
	})

	t.Run("custom limit truncates to N", func(t *testing.T) {
		got := buildJudgePrompt(req, "policy", 128)
		if !strings.Contains(got, "…") {
			t.Fatalf("expected ellipsis marking truncation, got prompt:\n%s", got)
		}
		if strings.Count(got, "Z") != 128 {
			t.Fatalf("expected exactly 128 body bytes after truncation, got %d",
				strings.Count(got, "Z"))
		}
	})
}
