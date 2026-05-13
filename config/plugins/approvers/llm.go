package approvers

// llm_approver: an LLM proctor that judges a request against the
// operator's policy text. Anthropic (api.anthropic.com) and OpenAI /
// codex (api.openai.com) wire through their bound credential's
// HTTPCredentialRuntime — same auth path the agent dispatcher uses
// for end-user requests, so OAuth refresh / per-profile rotation
// come for free.
//
// Model dispatch is name-prefixed: `claude-…` → Anthropic Messages
// API, `gpt-…` / `o*-…` → OpenAI Responses API.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

const llmJudgeSystem = `You are a security gate. Decide whether the operator's policy intends the gateway to ALLOW or DENY this request. The policy text is the source of truth.

Reply with EXACTLY one word on the first line: "allow" or "deny" (lowercase, no punctuation).
Then a brief one-line reason on the second line.

Be conservative — when the policy is ambiguous about whether the request is permitted, deny.`

const llmClassifierSystem = `You are a request classifier. Analyze the request against the policy and return a JSON classification.

Reply with JSON only — no markdown fences, no other text:
{"ticket_id":"<ticket id from path or body, or empty string>","classification":"<label per policy>","confidence":<0-100>,"summary":"<one sentence>"}`

// LLMApprover carries the model + the credential used to authenticate
// the call to the model API + the policy text the model judges
// against. Inline `policy` is a bare-name reference to a `policy
// "<name>" { text = ... }` block — operator declares the prompt once
// and reuses across multiple judges.
type LLMApprover struct {
	Model      string `hcl:"model"`
	Credential string `hcl:"credential"`
	Policy     string `hcl:"policy,optional"`
}

// Approve is part of the clawpatrol plugin API.
func (a *LLMApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if a.Model == "" {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "llm approver has no model"}, nil
	}
	if a.Credential == "" {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "llm approver has no credential"}, nil
	}
	if req.Policy == nil {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "no policy on request"}, nil
	}
	var policyText string
	if a.Policy != "" {
		pt, ok := req.Policy.Policies[a.Policy]
		if !ok {
			return runtime.ApproveVerdict{Decision: "deny", Reason: "policy " + a.Policy + " not declared"}, nil
		}
		policyText = pt.Text
	}
	if _, ok := req.Policy.Credentials[a.Credential]; !ok {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "credential " + a.Credential + " not declared"}, nil
	}

	user := buildJudgePrompt(req, policyText)

	var (
		hreq   *http.Request
		decode func(io.Reader) (string, error)
	)
	switch {
	case strings.HasPrefix(a.Model, "claude-"):
		hreq, decode = anthropicJudgeRequest(ctx, a.Model, llmJudgeSystem, user)
	case strings.HasPrefix(a.Model, "gpt-"), strings.HasPrefix(a.Model, "o"):
		hreq, decode = openaiJudgeRequest(ctx, a.Model, llmJudgeSystem, user)
	default:
		return runtime.ApproveVerdict{Decision: "deny", Reason: "unknown model family: " + a.Model}, nil
	}

	credEnt := req.Policy.Credentials[a.Credential]
	injector, ok := credEnt.Body.(runtime.HTTPCredentialRuntime)
	if !ok {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "credential " + a.Credential + " does not satisfy HTTPCredentialRuntime"}, nil
	}
	sec, err := req.Secrets.Get(a.Credential, req.Profile)
	if err != nil {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "secret fetch: " + err.Error()}, nil
	}
	if err := injector.InjectHTTP(ctx, hreq, sec); err != nil {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "credential inject: " + err.Error()}, nil
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(hreq)
	if err != nil {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "llm call: " + err.Error()}, nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return runtime.ApproveVerdict{Decision: "deny", Reason: fmt.Sprintf("llm http %d: %s", resp.StatusCode, string(body))}, nil
	}
	text, err := decode(resp.Body)
	if err != nil {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "llm response decode: " + err.Error()}, nil
	}
	verdict, reason := parseJudgeVerdict(text)
	by := "llm:" + a.Model
	return runtime.ApproveVerdict{Decision: verdict, Reason: reason, By: by}, nil
}

func buildJudgePrompt(req runtime.ApproveRequest, policyText string) string {
	var sb strings.Builder
	sb.WriteString("Policy:\n")
	if policyText != "" {
		sb.WriteString(policyText)
	} else if req.Reason != "" {
		sb.WriteString(req.Reason)
	} else {
		sb.WriteString("(none — fall back to default-deny when uncertain)")
	}
	sb.WriteString("\n\nRequest:\n")
	fmt.Fprintf(&sb, "  method: %s\n  host: %s\n  path: %s\n", req.Method, req.Host, req.Path)
	if req.UA != "" {
		fmt.Fprintf(&sb, "  user-agent: %s\n", req.UA)
	}
	if req.BodySample != "" {
		fmt.Fprintf(&sb, "  body:\n%s\n", indent(truncate(req.BodySample, 4000), "    "))
	}
	return sb.String()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func parseJudgeVerdict(text string) (string, string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "deny", "llm returned empty response"
	}
	lines := strings.SplitN(text, "\n", 2)
	first := strings.ToLower(strings.TrimSpace(lines[0]))
	first = strings.Trim(first, ".,;:!?\"'`")
	reason := ""
	if len(lines) > 1 {
		reason = strings.TrimSpace(lines[1])
	}
	switch first {
	case "allow":
		return "allow", reason
	case "deny":
		return "deny", reason
	default:
		// Best-effort: search for the verdict word anywhere in the
		// response. Models occasionally preface with "Verdict: …".
		lower := strings.ToLower(text)
		if strings.Contains(lower, "deny") && !strings.Contains(lower, "allow") {
			return "deny", text
		}
		if strings.Contains(lower, "allow") && !strings.Contains(lower, "deny") {
			return "allow", text
		}
		return "deny", "ambiguous llm response: " + truncate(text, 200)
	}
}

// anthropicJudgeRequest builds a /v1/messages call. The credential
// plugin's InjectHTTP stamps Authorization + the OAuth beta header
// when needed; we just frame the body.
func anthropicJudgeRequest(ctx context.Context, model, system, user string) (*http.Request, func(io.Reader) (string, error)) {
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 512,
		"system":     system,
		"messages": []map[string]any{
			{"role": "user", "content": user},
		},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	decode := func(r io.Reader) (string, error) {
		var msg struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.NewDecoder(r).Decode(&msg); err != nil {
			return "", err
		}
		for _, c := range msg.Content {
			if c.Type == "text" && c.Text != "" {
				return c.Text, nil
			}
		}
		return "", fmt.Errorf("anthropic response had no text content")
	}
	return req, decode
}

// openaiJudgeRequest builds a /v1/responses call (the modern GPT
// API). Authorization is supplied by the credential plugin's
// InjectHTTP.
func openaiJudgeRequest(ctx context.Context, model, system, user string) (*http.Request, func(io.Reader) (string, error)) {
	body, _ := json.Marshal(map[string]any{
		"model": model,
		"input": []map[string]any{
			{"role": "system", "content": []map[string]any{{"type": "input_text", "text": system}}},
			{"role": "user", "content": []map[string]any{{"type": "input_text", "text": user}}},
		},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://api.openai.com/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	decode := func(r io.Reader) (string, error) {
		var msg struct {
			Output []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		}
		if err := json.NewDecoder(r).Decode(&msg); err != nil {
			return "", err
		}
		for _, o := range msg.Output {
			for _, c := range o.Content {
				if c.Text != "" {
					return c.Text, nil
				}
			}
		}
		return "", fmt.Errorf("openai response had no output text")
	}
	return req, decode
}

// Summarize implements runtime.HITLClassifier. It calls the LLM in
// "summary mode" — sends the classifier system prompt and asks for a
// structured JSON classification instead of an allow/deny verdict.
// On parse failure or LLM error, returns nil, err so the caller can
// fall back to the generic card.
func (a *LLMApprover) Summarize(ctx context.Context, req runtime.ApproveRequest) (*runtime.HITLSummary, error) {
	if a.Model == "" {
		return nil, fmt.Errorf("llm classifier has no model")
	}
	if a.Credential == "" {
		return nil, fmt.Errorf("llm classifier has no credential")
	}
	if req.Policy == nil {
		return nil, fmt.Errorf("no policy on request")
	}
	var policyText string
	if a.Policy != "" {
		pt, ok := req.Policy.Policies[a.Policy]
		if !ok {
			return nil, fmt.Errorf("policy %s not declared", a.Policy)
		}
		policyText = pt.Text
	}
	if _, ok := req.Policy.Credentials[a.Credential]; !ok {
		return nil, fmt.Errorf("credential %s not declared", a.Credential)
	}

	user := buildClassifierPrompt(req, policyText)

	var (
		hreq   *http.Request
		decode func(io.Reader) (string, error)
	)
	switch {
	case strings.HasPrefix(a.Model, "claude-"):
		hreq, decode = anthropicJudgeRequest(ctx, a.Model, llmClassifierSystem, user)
	case strings.HasPrefix(a.Model, "gpt-"), strings.HasPrefix(a.Model, "o"):
		hreq, decode = openaiJudgeRequest(ctx, a.Model, llmClassifierSystem, user)
	default:
		return nil, fmt.Errorf("unknown model family: %s", a.Model)
	}

	credEnt := req.Policy.Credentials[a.Credential]
	injector, ok := credEnt.Body.(runtime.HTTPCredentialRuntime)
	if !ok {
		return nil, fmt.Errorf("credential %s does not satisfy HTTPCredentialRuntime", a.Credential)
	}
	sec, err := req.Secrets.Get(a.Credential, req.Profile)
	if err != nil {
		return nil, fmt.Errorf("secret fetch: %w", err)
	}
	if err := injector.InjectHTTP(ctx, hreq, sec); err != nil {
		return nil, fmt.Errorf("credential inject: %w", err)
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("llm http %d: %s", resp.StatusCode, string(body))
	}
	text, err := decode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("llm response decode: %w", err)
	}
	text = strings.TrimSpace(text)
	var summary runtime.HITLSummary
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		return nil, fmt.Errorf("classifier json parse: %w (raw: %s)", err, truncate(text, 200))
	}
	return &summary, nil
}

func buildClassifierPrompt(req runtime.ApproveRequest, policyText string) string {
	var sb strings.Builder
	sb.WriteString("Policy:\n")
	if policyText != "" {
		sb.WriteString(policyText)
	} else if req.Reason != "" {
		sb.WriteString(req.Reason)
	} else {
		sb.WriteString("(none)")
	}
	sb.WriteString("\n\nRequest:\n")
	fmt.Fprintf(&sb, "  method: %s\n  host: %s\n  path: %s\n", req.Method, req.Host, req.Path)
	if req.UA != "" {
		fmt.Fprintf(&sb, "  user-agent: %s\n", req.UA)
	}
	if req.BodySample != "" {
		fmt.Fprintf(&sb, "  body:\n%s\n", indent(truncate(req.BodySample, 4000), "    "))
	}
	return sb.String()
}

// compile-time assertion that LLMApprover satisfies HITLClassifier.
var _ runtime.HITLClassifier = (*LLMApprover)(nil)

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindApprover,
		Type:    "llm_approver",
		New:     func() any { return &LLMApprover{} },
		Runtime: (*LLMApprover)(nil),
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential},
			{Path: "Policy", Kind: config.KindPolicy, Optional: true},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*LLMApprover)
			b.SetAttributeValue("model", cty.StringVal(a.Model))
			config.SetIdent(b, "credential", a.Credential)
			if a.Policy != "" {
				config.SetIdent(b, "policy", a.Policy)
			}
		},
	})
}
