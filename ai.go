package main

// Natural-language → rule HCL via a connected LLM provider.
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

	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/denoland/clawpatrol/config"
)

const ruleSystemPrompt = `You edit clawpatrol gateway policy expressed in the v14 typed-block HCL grammar.

# Grammar

A rule is a top-level block with one label: rule NAME { ... }. The
rule's protocol family (https / sql / k8s) is inferred from the
endpoint(s) it targets — all endpoints on one rule must be from the
same family.

Body shape:

  rule "name-of-rule" {
    endpoint   = some-endpoint                   # bare-name ref (no quotes)
    # endpoints = [a, b]                          # list form for multi-endpoint
    priority   = 100                              # optional; default 0
    disabled   = false                            # optional
    credential = some-credential                  # optional bare-name ref
    condition  = "<CEL expression>"               # optional; absent/"" = match-everything
    verdict    = "allow"                          # OR  approve = [name1, name2]
    reason     = "human-readable"                 # required when verdict = "deny"
  }

Exactly one of verdict / approve must be set.

# Per-family CEL variables

Each family exposes a single struct-typed variable. Fields are
accessed via dot notation.

https endpoints:  http.method, http.path,
                  http.query (map<string,list<string>>),
                  http.headers (map<string,list<string>>),
                  http.body (string), http.body_json (dyn)
sql endpoints:    sql.verb (lower-case), sql.tables (list<string>),
                  sql.functions (list<string>), sql.statement (string)
k8s endpoints:    k8s.resource, k8s.verb (lower-case),
                  k8s.namespace, k8s.name,
                  k8s.params (map<string,string>)

Use CEL operators / builtins: ==, !=, &&, ||, !, in, startsWith,
endsWith, contains, matches (regex), size().

Examples:

  condition = "http.method in ['POST', 'DELETE']"
  condition = "'secrets' in sql.tables || sql.tables.exists(t, t.startsWith('audit.'))"
  condition = "sql.verb == 'drop'"
  condition = "k8s.resource == 'secrets' && k8s.verb in ['get', 'list']"
  condition = "!k8s.name.startsWith('debug-')"
  condition = "sql.statement.matches('(?i)copy.*from program')"
  condition = "http.body.contains('approve_reply_')"
  condition = "http.body_json.archived == true"

# References

All cross-block references are BARE NAMES (no quotes, no dotted prefix):

  endpoint = stripe-live           # not "stripe-live"
  approve  = [billing, dashboard]  # not ["billing", "dashboard"]

A flat namespace is shared across endpoints / credentials / rules /
approvers / policies / profiles — names must be globally unique.

# What you may emit

Any top-level block (credential, endpoint, rule, approver, policy,
profile). When the request needs a host that isn't covered by an
existing endpoint, ADD an endpoint block (and any required credential),
then add the rule. Per-device overrides are not supported — scope
changes happen at the profile level.

# Output rules — STRICT

- Your output is fed straight to an HCL parser. Output MUST be valid
  HCL. NEVER emit prose, refusal text, apologies, explanations,
  questions, or markdown fences. The first character of your reply
  must be either '#' (a comment line) or the start of an HCL
  attribute / block.

- Preserve every block / rule that you weren't explicitly asked to
  change. Output the FULL document, not a diff.

- "ask before X" / "approve X" → set approve = [<approver-name>] on a
  matching rule. dashboard is always available; other approvers must
  be declared via approver "<type>" "<name>" blocks elsewhere.

- Cross-references must resolve. Either the bare name is in the
  "Available references" list (use it as-is), OR you DECLARE the
  block yourself in the same output (and then the bare name resolves
  to your new declaration). Do not reference a name without one of
  these two paths — that's a hard load error.

  Example for "block GET to deno.com" when deno isn't declared:
  EMIT a new ` + "`endpoint \"https\" \"deno\" { hosts = [\"deno.com\"] }`" + `
  block, then reference ` + "`endpoint = deno`" + ` in the rule. Do NOT
  refuse just because deno isn't in the available list.

# Endpoints don't require credentials

The credential field on an endpoint is OPTIONAL. For block-only or
passthrough hosts (anything you only want to deny / inspect / audit
but not inject auth for), OMIT the credential entirely:

  endpoint "https" "deno" {
    hosts = ["deno.com"]
  }

Do NOT refuse because "no credential is available." Most deny-only
endpoints don't need one. Add a credential only when the operator
asked you to inject auth.

# Default disposition: WRITE THE HCL

Refuse only when structurally impossible (e.g. the operator asked
for SQL match facets on a github endpoint, which is wrong family).
Anything that is "I need to add an endpoint and a rule" is
satisfiable — just write the HCL.

- No legacy keys — host, sql_verb, action, swap, mtls block
  on a rule, account match key are ALL legacy. Don't emit them.

# When you cannot satisfy the request

You must STILL emit valid HCL. Choose ONE of:

  (a) The request is ambiguous, dangerous, or requires names that
      aren't declared: emit the input unchanged with a single
      sentinel comment as the FIRST line of the document:

        # AI_REFUSED: <one-sentence reason — declared names missing,
        # ambiguous predicate, etc.>

      Then the unchanged input. The server strips the sentinel and
      surfaces the reason to the operator without touching the editor.

  (b) The request is satisfiable but with caveats: emit the new
      document and an extra comment line above the changed block:

        # AI_NOTE: <one-sentence note about a tradeoff or assumption>

Never reply with bare prose. The parser will reject it and the
operator sees a confusing error.`

// generateRuleHCL returns (newHCL, refused, error).
//
//   - newHCL: the AI's edit (validated as parseable HCL). Empty only
//     when refused is non-empty — caller should NOT replace the editor.
//   - refused: human-readable reason from an AI_REFUSED sentinel. When
//     set, newHCL is empty and the dashboard surfaces the reason
//     without changing the editor contents.
//   - error: transport / model failure (caller renders verbatim).
//
// The function never returns prose-as-HCL — if the model output fails
// to parse it returns an error instead, so the dashboard can show a
// clean "AI returned invalid HCL" rather than splatting prose into
// the editor.
func generateRuleHCL(ctx context.Context, g *Gateway, agent, owner, prompt, currentHCL, scope string) (newHCL, refused string, err error) {
	reg := g.oauth
	if agent == "" {
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
		return "", "", fmt.Errorf("no connected LLM provider — connect Claude or Codex first")
	}
	symbols := availableSymbols(g.Policy())
	user := fmt.Sprintf(
		"Scope: %s\n\n%s\n\nCurrent HCL:\n\n%s\n\nApply this change:\n\n%s",
		scopeLabel(scope), symbols, currentHCL, prompt,
	)
	var raw string
	switch agent {
	case "claude":
		raw, err = callClaude(ctx, reg, owner, user)
	case "codex":
		raw, err = callCodex(ctx, reg, owner, user)
	default:
		return "", "", fmt.Errorf("unknown agent: %s", agent)
	}
	if err != nil {
		return "", "", err
	}
	out, refusal := extractRefusal(raw)
	if refusal != "" {
		return "", refusal, nil
	}
	if perr := validateHCLSyntax(out); perr != nil {
		return "", "", fmt.Errorf("AI returned invalid HCL — %w", perr)
	}
	return out, "", nil
}

// extractRefusal pulls a leading AI_REFUSED sentinel comment out of the
// model output. Returns the cleaned HCL and the refusal text. When no
// sentinel is present, returns the input unchanged and "".
func extractRefusal(s string) (string, string) {
	s = strings.TrimSpace(s)
	const tag = "# AI_REFUSED:"
	if !strings.HasPrefix(s, tag) {
		return s, ""
	}
	// Comment may span multiple lines if each starts with '#'. Eat
	// every leading '#'-prefixed line; collapse them into one
	// reason string.
	var reason strings.Builder
	rest := s
	for {
		nl := strings.IndexByte(rest, '\n')
		if nl < 0 {
			line := strings.TrimSpace(rest)
			if !strings.HasPrefix(line, "#") {
				break
			}
			reason.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "#")))
			rest = ""
			break
		}
		line := strings.TrimSpace(rest[:nl])
		if !strings.HasPrefix(line, "#") {
			break
		}
		txt := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		txt = strings.TrimPrefix(txt, "AI_REFUSED:")
		txt = strings.TrimSpace(txt)
		if txt != "" {
			if reason.Len() > 0 {
				reason.WriteByte(' ')
			}
			reason.WriteString(txt)
		}
		rest = rest[nl+1:]
	}
	return strings.TrimSpace(rest), reason.String()
}

// validateHCLSyntax confirms the output parses as HCL. We only care
// about syntax here — full type-check happens during the gateway.hcl
// preview/save flow.
func validateHCLSyntax(s string) error {
	parser := hclparse.NewParser()
	_, diags := parser.ParseHCL([]byte(s), "ai.hcl")
	if diags.HasErrors() {
		return fmt.Errorf("%s", diags.Error())
	}
	return nil
}

// availableSymbols renders the loaded policy's reference set so the
// AI knows which bare names it can emit. Without this it tends to
// hallucinate endpoint / approver names that don't exist.
func availableSymbols(policy *config.CompiledPolicy) string {
	if policy == nil {
		return "Available references: (policy not loaded)"
	}
	endpoints := make([]string, 0, len(policy.Endpoints))
	for name, ep := range policy.Endpoints {
		endpoints = append(endpoints, fmt.Sprintf("%s (%s)", name, ep.Family))
	}
	credentials := make([]string, 0, len(policy.Credentials))
	for name, ent := range policy.Credentials {
		credentials = append(credentials, fmt.Sprintf("%s (%s)", name, ent.Plugin.Type))
	}
	approvers := []string{"dashboard (built-in)"}
	for name, ent := range policy.Approvers {
		approvers = append(approvers, fmt.Sprintf("%s (%s)", name, ent.Plugin.Type))
	}
	policies := make([]string, 0, len(policy.Policies))
	for name := range policy.Policies {
		policies = append(policies, name)
	}
	return fmt.Sprintf(
		"Available references (use bare names, no quotes):\n  endpoints:   %s\n  credentials: %s\n  approvers:   %s\n  policies:    %s",
		strings.Join(endpoints, ", "),
		strings.Join(credentials, ", "),
		strings.Join(approvers, ", "),
		strings.Join(policies, ", "),
	)
}

func scopeLabel(_ string) string { return "global" }

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
	defer func() { _ = resp.Body.Close() }()
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
			return cleanCodeFences(c.Text), nil
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
	defer func() { _ = resp.Body.Close() }()
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
				return cleanCodeFences(c.Text), nil
			}
		}
	}
	return "", fmt.Errorf("openai: no text content in response")
}

// cleanCodeFences strips ```hcl / ```yaml / ``` markdown fences if the
// model included them despite instructions.
func cleanCodeFences(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"```hcl", "```HCL", "```yaml", "```YAML", "```"} {
		if strings.HasPrefix(s, p) {
			s = strings.TrimPrefix(s, p)
			break
		}
	}
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
