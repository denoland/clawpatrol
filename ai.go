package main

// Natural-language → rule YAML via a connected LLM provider.
// Reuses the operator's existing Claude/Codex OAuth credentials so
// there's no separate API key to manage.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const ruleSystemPrompt = `You translate natural-language gateway-policy requests into clawpatrol rule YAML.

A clawpatrol rule is YAML matching this schema:

  - host: example.com           # required, exact host or glob
    device: 100.64.x.y          # optional, scopes to one device IP
    match:                       # optional, request-level filters
      method: [POST, DELETE]
      path: /api/foo
    action: deny                 # optional: "deny" rejects with 403
                                 #          "hitl" pauses for human approval via dashboard
    reason: ...                  # optional explanation (shown to operator on hitl prompts)
    hitl_timeout: 60             # optional, seconds to wait for approval (default 60)
    headers:                     # optional, add/override request headers
      Authorization: "Bearer {{secret:NAME}}"
    swap:                        # optional, body string substitutions
      - placeholder: PLACEHOLDER
        secret: "{{secret:NAME}}"
    body: true                   # optional, enable body scan-replace
    auth: claude                 # optional, OAuth integration to inject
    track: claude_usage          # optional: claude_usage | openai_usage
    ws_scan: true                # optional, intercept WS frames
    upstream: real-host.com      # optional, override upstream host
    port: 443                    # optional
    mtls:                        # optional, present a client cert at the upstream
      ca: /etc/clawpatrol/k8s-ca.pem
      cert: /etc/clawpatrol/k8s-client.crt
      key:  /etc/clawpatrol/k8s-client.key

Rules are evaluated in order; first match wins. Device-scoped rules
take precedence over global ones.

OUTPUT RULES — read carefully:
- Output ONLY the YAML — no prose, no markdown fences.
- Preserve every existing rule UNLESS the user explicitly asks to remove
  or change it.
- For "deny X on Y" requests, append a deny rule with the appropriate
  match clause (method/path) BEFORE any catch-all rule for that host.
- For "ask before X" / "prompt before X" / "approve X" requests, use
  action: hitl with the same matching pattern.
- Keys must use the exact names listed above.
- If you can't satisfy the request, output the original YAML unchanged.`

func generateRuleYAML(ctx context.Context, reg *OAuthRegistry, agent, owner, prompt, currentYAML, scope string) (string, error) {
	if agent == "" {
		// pick whichever is connected
		for _, id := range []string{"claude", "codex"} {
			if owners := reg.Owners(id); len(owners) > 0 {
				for _, o := range owners {
					if o == owner {
						agent = id
						break
					}
				}
			}
			if agent != "" {
				break
			}
		}
	}
	if agent == "" {
		return "", fmt.Errorf("no connected LLM provider — connect Claude or Codex first")
	}
	user := fmt.Sprintf("Current %s rules YAML:\n\n%s\n\nApply this change:\n\n%s",
		scopeLabel(scope), currentYAML, prompt)
	switch agent {
	case "claude":
		return callClaude(ctx, reg, owner, user)
	case "codex":
		return callCodex(ctx, reg, owner, user)
	}
	return "", fmt.Errorf("unknown agent: %s", agent)
}

func scopeLabel(s string) string {
	if s == "device" {
		return "device-specific"
	}
	return "global"
}

// callClaude hits Anthropic's /v1/messages with the rule system prompt.
// Uses the operator's OAuth credential — Inject() adds the Authorization
// header to a freshly-built request.
func callClaude(ctx context.Context, reg *OAuthRegistry, owner, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":      "claude-haiku-4-5",
		"max_tokens": 4096,
		"system":     ruleSystemPrompt,
		"messages": []map[string]any{
			{"role": "user", "content": user},
		},
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	if _, err := reg.Inject("claude", owner, req); err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("anthropic %d: %s", resp.StatusCode, truncate(string(rb), 400))
	}
	var msg struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(rb, &msg); err != nil {
		return "", err
	}
	for _, c := range msg.Content {
		if c.Type == "text" && c.Text != "" {
			return cleanYAMLFences(c.Text), nil
		}
	}
	return "", fmt.Errorf("anthropic: no text content in response")
}

// callCodex routes through the OpenAI Responses API. Mirrors callClaude
// for the Codex OAuth integration. Uses gpt-5-mini (fast, cheap) for
// rule generation.
func callCodex(ctx context.Context, reg *OAuthRegistry, owner, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": "gpt-5-mini",
		"input": []map[string]any{
			{"role": "system", "content": []map[string]any{{"type": "input_text", "text": ruleSystemPrompt}}},
			{"role": "user", "content": []map[string]any{{"type": "input_text", "text": user}}},
		},
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.openai.com/v1/responses", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if _, err := reg.Inject("codex", owner, req); err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("openai %d: %s", resp.StatusCode, truncate(string(rb), 400))
	}
	var r struct {
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(rb, &r); err != nil {
		return "", err
	}
	for _, o := range r.Output {
		for _, c := range o.Content {
			if c.Text != "" {
				return cleanYAMLFences(c.Text), nil
			}
		}
	}
	return "", fmt.Errorf("openai: no text content in response")
}

// cleanYAMLFences strips ```yaml ... ``` markdown fences if the model
// included them despite instructions.
func cleanYAMLFences(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```yaml")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
