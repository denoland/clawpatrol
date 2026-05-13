package credentials

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config/runtime"
)

// findBlock returns the first block in blocks whose "type" matches.
func findBlock(blocks []map[string]any, kind string) map[string]any {
	for _, b := range blocks {
		if b["type"] == kind {
			return b
		}
	}
	return nil
}

// findSectionContaining returns the first "section" block whose
// mrkdwn text contains the given substring.
func findSectionContaining(blocks []map[string]any, sub string) map[string]any {
	for _, b := range blocks {
		if b["type"] != "section" {
			continue
		}
		txt, _ := b["text"].(map[string]any)
		if txt == nil {
			continue
		}
		s, _ := txt["text"].(string)
		if strings.Contains(s, sub) {
			return b
		}
	}
	return nil
}

func sectionText(t *testing.T, b map[string]any) string {
	t.Helper()
	txt, ok := b["text"].(map[string]any)
	if !ok {
		t.Fatalf("section has no text block: %v", b)
	}
	s, _ := txt["text"].(string)
	return s
}

func TestBuildSlackHITLBlocksDefaultBody(t *testing.T) {
	req := runtime.ApproveRequest{
		Method: "POST",
		Host:   "api.example.com",
		Path:   "/v1/repos",
	}
	target := runtime.HITLTarget{
		PendingID:    "abc123",
		DashboardURL: "https://dash.example.com",
	}
	title, blocks := buildSlackHITLBlocks(req, target)
	if !strings.Contains(title, "POST") {
		t.Errorf("title = %q, want POST", title)
	}
	body := findSectionContaining(blocks, "/v1/repos")
	if body == nil {
		t.Fatalf("default body missing path; blocks: %s", dumpJSON(blocks))
	}
	if strings.Contains(sectionText(t, body), "operator-authored") {
		t.Errorf("default body should not contain template content")
	}
}

func TestBuildSlackHITLBlocksUsesTemplateMessage(t *testing.T) {
	req := runtime.ApproveRequest{
		Method: "POST",
		Host:   "api.example.com",
		Path:   "/v1/repos",
	}
	target := runtime.HITLTarget{
		PendingID:    "abc123",
		DashboardURL: "https://dash.example.com",
		Message:      "agent 10.0.0.1 wants to POST /v1/repos",
	}
	_, blocks := buildSlackHITLBlocks(req, target)
	body := findSectionContaining(blocks, "agent 10.0.0.1 wants to POST")
	if body == nil {
		t.Fatalf("template message missing from blocks: %s", dumpJSON(blocks))
	}
	// Default Path-code-fence body should NOT appear when a template
	// message is rendered — the template owns the prompt.
	if findSectionContaining(blocks, "```/v1/repos```") != nil {
		t.Errorf("default path-code-fence still rendered alongside template message")
	}
}

func TestBuildSlackHITLBlocksTemplateBeatsSummary(t *testing.T) {
	// When both Summary (classifier) and Message (template) are
	// present, the operator's explicit template wins — they asked
	// for that exact text.
	req := runtime.ApproveRequest{Method: "POST", Path: "/x"}
	target := runtime.HITLTarget{
		Message: "explicit template body",
		Summary: &runtime.HITLSummary{
			TicketID:       "TKT-42",
			Classification: "Legit",
			Text:           "classifier summary text",
		},
	}
	_, blocks := buildSlackHITLBlocks(req, target)
	if findSectionContaining(blocks, "explicit template body") == nil {
		t.Errorf("template message missing")
	}
	if findSectionContaining(blocks, "classifier summary text") != nil {
		t.Errorf("classifier summary leaked into prompt despite template")
	}
}

func TestBuildSlackHITLBlocksTemplateKeepsContextAndButtons(t *testing.T) {
	req := runtime.ApproveRequest{
		Method:  "POST",
		AgentIP: "10.0.0.7",
		Reason:  "writes go through ops",
		Path:    "/x",
	}
	target := runtime.HITLTarget{
		PendingID:   "abc",
		Interactive: true,
		Message:     "hello operator",
	}
	_, blocks := buildSlackHITLBlocks(req, target)
	if findBlock(blocks, "context") == nil {
		t.Errorf("context block missing")
	}
	if findBlock(blocks, "actions") == nil {
		t.Errorf("actions block missing")
	}
}

func dumpJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
