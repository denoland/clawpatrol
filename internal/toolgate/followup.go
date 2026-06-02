package toolgate

// Gateway-initiated LLM choice for the HITL polling tool ("option 2").
//
// The earlier draft swapped a HITL tool_use for a synthesised
// `clawpatrol_poll` tool_use. That is broken: the agent's tool
// dispatcher is built from the tools the agent registered locally, so a
// tool clawpatrol invents has no handler and can never execute. The
// agent must be told to poll using a tool it already advertises.
//
// Rather than have the gateway guess which of the agent's tools can make
// an HTTP request, this path lets the model pick. The gateway acts as
// one iteration of the agent loop:
//
//  1. Take the upstream assistant response and remove the parked
//     (HITL'd) tool_use blocks from it.
//  2. Fabricate a user message instructing the model to poll
//     clawpatrol's approval endpoint, choosing the right tool from the
//     agent's own advertised tools[].
//  3. Make clawpatrol's *own* upstream /v1/messages call (reusing the
//     agent's credentials and tool set) — an LLMCaller supplied by the
//     cmd layer.
//  4. Forward the follow-up response to the agent. It now names a tool
//     the agent actually has, so the agent executes it and polls.
//
// The package stays transport-agnostic: the LLMCaller hides the MITM
// transport / credential machinery (which lives in cmd/clawpatrol), so
// the follow-up dance is unit-testable with a fake caller.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// LLMCaller performs a gateway-initiated /v1/messages round-trip. It is
// handed a complete Anthropic request body (JSON) and returns the
// upstream response body (JSON, decoded — caller handles any transport
// encoding). The cmd/clawpatrol layer supplies the real implementation
// (clone the credential-injected request, swap the body, RoundTrip);
// tests pass a fake. A nil caller disables option 2 — the HITL path then
// degrades to a coherent "approval pending" text block.
type LLMCaller func(ctx context.Context, requestBody []byte) (responseBody []byte, err error)

// FollowupConfig carries everything the gateway-initiated follow-up
// needs. The allow/deny paths ignore it; only HITL consults it. Zero
// value (nil Caller) disables the follow-up.
type FollowupConfig struct {
	// ReqBody is the agent's original /v1/messages request body, used to
	// rebuild the conversation (messages + tools + model + system…). When
	// empty (e.g. the gateway couldn't buffer the full body), the
	// follow-up is skipped and the HITL path falls back to a text block.
	ReqBody []byte
	// Caller performs clawpatrol's own upstream LLM call. Nil disables the
	// follow-up.
	Caller LLMCaller
	// ApprovalURL is the base URL the agent's polling tool should target
	// (it hits ApprovalURL + "/api/approval/poll"). Empty falls back to
	// DefaultApprovalBaseURL.
	ApprovalURL string
}

// DefaultApprovalBaseURL is the placeholder base URL woven into the
// fabricated polling instruction when FollowupConfig.ApprovalURL is
// unset. It is intentionally a stand-in: operators must point
// CLAWPATROL_TOOLGATE_APPROVAL_URL at clawpatrol's agent-reachable base
// URL for the polling tool call to actually connect.
const DefaultApprovalBaseURL = "http://clawpatrol.local"

// errNoFollowupCaller signals that option 2 is unavailable for this turn
// (no caller wired, or no original request body to rebuild from). The
// HITL path treats it as "fall back to the pending-approval text block",
// never as a hard failure.
var errNoFollowupCaller = errors.New("toolgate: no follow-up LLM caller configured")

func approvalBaseURL(fc *FollowupConfig) string {
	if fc != nil && fc.ApprovalURL != "" {
		return fc.ApprovalURL
	}
	return DefaultApprovalBaseURL
}

// runFollowup performs the gateway-initiated LLM call: it rebuilds the
// conversation from the original request plus the (tool_use-stripped)
// assistant response plus a polling instruction, then calls the model.
// It returns the follow-up response body — a real Anthropic response
// whose tool_use names one of the agent's own tools. Callers forward it
// to the agent (JSON path verbatim, SSE path re-emitted as frames).
func runFollowup(ctx context.Context, fc *FollowupConfig, respBody []byte, parked []*PendingCall) ([]byte, error) {
	if fc == nil || fc.Caller == nil || len(fc.ReqBody) == 0 {
		return nil, errNoFollowupCaller
	}
	reqBody, err := buildFollowupRequest(fc.ReqBody, respBody, parked, approvalBaseURL(fc))
	if err != nil {
		return nil, err
	}
	resp, err := fc.Caller(ctx, reqBody)
	if err != nil {
		return nil, fmt.Errorf("toolgate follow-up call: %w", err)
	}
	if len(resp) == 0 {
		return nil, errors.New("toolgate follow-up: empty response body")
	}
	return resp, nil
}

// buildFollowupRequest rebuilds the agent's /v1/messages request for the
// gateway-initiated polling-tool choice. The new conversation is:
//
//	<original messages…>
//	assistant: <original response content, tool_use blocks removed>
//	user:      <instruction to poll the approval endpoint>
//
// tools / model / system / max_tokens and every other top-level field
// are carried over verbatim so the model picks from the agent's own
// advertised tools. stream is forced false so the caller gets one
// buffered JSON response.
func buildFollowupRequest(origReqBody, respBody []byte, parked []*PendingCall, approvalURL string) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(origReqBody, &raw); err != nil {
		return nil, fmt.Errorf("toolgate follow-up: original request parse: %w", err)
	}
	msgsRaw, ok := raw["messages"]
	if !ok {
		return nil, errors.New("toolgate follow-up: original request has no messages[]")
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(msgsRaw, &messages); err != nil {
		return nil, fmt.Errorf("toolgate follow-up: messages parse: %w", err)
	}

	assistantContent, err := strippedAssistantContent(respBody)
	if err != nil {
		return nil, err
	}
	assistantMsg, err := json.Marshal(map[string]any{
		"role":    "assistant",
		"content": assistantContent,
	})
	if err != nil {
		return nil, fmt.Errorf("toolgate follow-up: assistant message marshal: %w", err)
	}
	userMsg, err := json.Marshal(map[string]any{
		"role":    "user",
		"content": pollingInstruction(parked, approvalURL),
	})
	if err != nil {
		return nil, fmt.Errorf("toolgate follow-up: user message marshal: %w", err)
	}

	messages = append(messages, json.RawMessage(assistantMsg), json.RawMessage(userMsg))
	newMsgs, err := json.Marshal(messages)
	if err != nil {
		return nil, fmt.Errorf("toolgate follow-up: messages marshal: %w", err)
	}
	raw["messages"] = newMsgs
	raw["stream"] = json.RawMessage("false")

	out, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("toolgate follow-up: request marshal: %w", err)
	}
	return out, nil
}

// strippedAssistantContent returns the upstream response's content blocks
// with every tool_use (and signature-bearing thinking) block removed,
// keeping the text rationale so the model sees what it was doing. When
// nothing survives, a single placeholder text block is returned so the
// assistant message is non-empty (Anthropic rejects empty content).
func strippedAssistantContent(respBody []byte) ([]json.RawMessage, error) {
	var resp struct {
		Content []json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("toolgate follow-up: response parse: %w", err)
	}
	kept := make([]json.RawMessage, 0, len(resp.Content))
	for _, blk := range resp.Content {
		var hdr struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(blk, &hdr); err != nil {
			continue
		}
		// Keep only plain text. tool_use is what we're parking; thinking
		// blocks carry signatures that don't survive a rebuilt request.
		if hdr.Type == "text" {
			kept = append(kept, blk)
		}
	}
	if len(kept) == 0 {
		placeholder, _ := json.Marshal(map[string]any{
			"type": "text",
			"text": "(A tool call requires approval before I can continue.)",
		})
		kept = append(kept, json.RawMessage(placeholder))
	}
	return kept, nil
}

// pollingInstruction is the fabricated user turn that tells the model to
// poll clawpatrol's approval endpoint using one of the agent's own tools.
// It deliberately names the parked tool(s), the token(s), and the exact
// HTTP shape so the model can pick whichever advertised tool makes an
// HTTP request (fetch, http_request, a shell that can curl, …).
func pollingInstruction(parked []*PendingCall, approvalURL string) string {
	pollURL := approvalURL + "/api/approval/poll"
	if len(parked) == 1 {
		pc := parked[0]
		return fmt.Sprintf(
			"The tool call to %q has been intercepted by clawpatrol and requires human "+
				"approval before it can run. It is now parked and pending review "+
				"(approval token: %s).\n\n"+
				"Do NOT call %q again. Instead, choose the single most appropriate tool "+
				"from the tools available to you that can make an HTTP request, and use it "+
				"to long-poll clawpatrol's approval endpoint for the decision:\n\n"+
				"  POST %s\n"+
				"  Content-Type: application/json\n"+
				"  Body: {\"token\": %q}\n\n"+
				"The endpoint blocks until a decision is made (or briefly times out) and "+
				"returns JSON {\"state\": \"pending\" | \"approved\" | \"denied\"}. If the "+
				"state is \"pending\", poll again. Once \"approved\" you may proceed; if "+
				"\"denied\", stop. Call exactly one polling tool now — do not output any "+
				"other tool call.",
			parked[0].ToolName, pc.Token, parked[0].ToolName, pollURL, pc.Token)
	}

	var b []byte
	b = append(b, "Several tool calls have been intercepted by clawpatrol and now require "...)
	b = append(b, "human approval before they can run. Each is parked and pending review:\n\n"...)
	for _, pc := range parked {
		b = append(b, fmt.Sprintf("  - %q (approval token: %s)\n", pc.ToolName, pc.Token)...)
	}
	b = append(b, fmt.Sprintf(
		"\nDo NOT call those tools again. Instead, choose the single most appropriate tool "+
			"from the tools available to you that can make an HTTP request, and use it to "+
			"long-poll clawpatrol's approval endpoint for each token:\n\n"+
			"  POST %s\n"+
			"  Content-Type: application/json\n"+
			"  Body: {\"token\": \"<one of the tokens above>\"}\n\n"+
			"The endpoint returns JSON {\"state\": \"pending\" | \"approved\" | \"denied\"}. "+
			"Poll while \"pending\"; proceed on \"approved\"; stop on \"denied\". Start by "+
			"polling the first token now using exactly one polling tool.",
		pollURL)...)
	return string(b)
}

// firstAgentBlock extracts the block the follow-up model chose, for the
// SSE path to re-emit at the held block's content index. It returns the
// first tool_use block (the expected outcome — the model picked a polling
// tool) as (name, id, inputJSON, true). If the follow-up produced no
// tool_use, it returns the concatenated text as ("", "", text, false) so
// the SSE path can emit a text block instead. A response with neither
// yields ("", "", "", false).
func firstAgentBlock(followupBody []byte) (name, id, payload string, isToolUse bool) {
	var resp struct {
		Content []struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
			Text  string          `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(followupBody, &resp); err != nil {
		return "", "", "", false
	}
	var text string
	for _, blk := range resp.Content {
		switch blk.Type {
		case "tool_use":
			input := string(blk.Input)
			if input == "" {
				input = "{}"
			}
			return blk.Name, blk.ID, input, true
		case "text":
			text += blk.Text
		}
	}
	return "", "", text, false
}
