package toolgate

// Anthropic /v1/messages response gating. Parses tool_use blocks out
// of the response body, applies the rule set, and rewrites the
// response shape according to the verdict — forwarding allow untouched,
// replacing deny with a refusal text block, and for HITL parking the
// call and running a gateway-initiated follow-up LLM call so the model
// picks a polling tool from the agent's own advertised tools (see
// followup.go).
//
// Only non-streaming JSON responses are handled here; the streaming
// SSE variant lives in anthropic_sse.go (GateAnthropicSSE), which
// applies the same verdicts block by block as the events arrive.
//
// Note the two paths differ on error handling. This JSON path fails
// OPEN — a parse error forwards the original body so a gating bug can't
// brick a legitimate non-tool turn. The streaming path fails CLOSED — a
// tool_use it can't evaluate is blocked, never forwarded raw.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// anthropicBlock is the discriminated-union over response content
// blocks. Only `type` is parsed eagerly; the rest is held verbatim
// for either pass-through or surgical rewrite via RawMessage merge.
type anthropicBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// Text is captured only for transparency; we never rewrite text
	// blocks in this draft.
	Text string `json:"text,omitempty"`
}

// GateOutcome is what a caller (the HTTPS MITM hook) gets back: the
// possibly-rewritten response bytes plus a slice of parked calls so
// the host can attach them to the request log / dashboard. ToolUsesSeen
// is the raw count of tool_use blocks in the original response — used
// by the test harness and the dashboard's "this turn was gated"
// indicator.
type GateOutcome struct {
	Body         []byte
	Parked       []*PendingCall
	ToolUsesSeen int
	// Rewrote reports whether the body bytes were changed. False when
	// the response carried no tool_uses or every tool_use matched an
	// allow rule.
	Rewrote bool
	// Notes are short human-readable strings about why the response
	// was rewritten — fed into the dashboard event log via the
	// existing ev.Reason field on the start/end event.
	Notes []string
}

// GateAnthropicResponse runs the rule set against the tool_use blocks
// in an Anthropic /v1/messages JSON response body. It returns the
// (possibly rewritten) body. Errors short-circuit to "no rewrite" —
// the gateway forwards the original response and logs the parse error;
// failing closed on a bad body would deny legitimate non-tool turns.
//
// When a tool_use matches a HITL rule the call is parked and a
// gateway-initiated follow-up LLM call (via fc) rebuilds the turn so the
// model picks a polling tool from the agent's own tools — see
// followup.go. The follow-up response is forwarded to the agent. If the
// follow-up is unavailable (nil fc/caller, missing request body) or
// fails, the HITL path degrades to a coherent "approval pending" text
// block rather than leaking the original tool call.
func GateAnthropicResponse(ctx context.Context, rules RuleSet, store *Store, body []byte, fc *FollowupConfig) (GateOutcome, error) {
	if len(body) == 0 {
		return GateOutcome{Body: body}, nil
	}

	// First parse into a raw object so we can walk content[] and
	// preserve every unknown sibling key on the way out — the model
	// will see exactly what came back from upstream apart from the
	// tool_use blocks we mutate.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return GateOutcome{Body: body}, fmt.Errorf("anthropic body parse: %w", err)
	}
	contentRaw, hasContent := raw["content"]
	if !hasContent {
		return GateOutcome{Body: body}, nil
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(contentRaw, &blocks); err != nil {
		return GateOutcome{Body: body}, fmt.Errorf("anthropic content parse: %w", err)
	}

	var (
		outcome   GateOutcome
		newBlocks = make([]json.RawMessage, 0, len(blocks))
		rewrote   bool
	)

	for _, blk := range blocks {
		var hdr anthropicBlock
		if err := json.Unmarshal(blk, &hdr); err != nil || hdr.Type != "tool_use" {
			newBlocks = append(newBlocks, blk)
			continue
		}
		outcome.ToolUsesSeen++

		argsJSON := string(hdr.Input)
		rule, matched := rules.Evaluate(hdr.Name, argsJSON)

		switch {
		case !matched, rule.Verdict == VerdictAllow:
			// Forward this block unchanged.
			newBlocks = append(newBlocks, blk)

		case rule.Verdict == VerdictDeny:
			rewrote = true
			outcome.Notes = append(outcome.Notes,
				fmt.Sprintf("deny tool_use name=%q rule=%q reason=%q",
					hdr.Name, rule.Name, rule.Reason))
			// Per the spec, on deny we drop the tool_use entirely.
			// The model's next turn (when the agent reflects the
			// missing call back through clawpatrol — or, more commonly,
			// when the gateway-side wrapper feeds a synthesised
			// tool_result on the agent's behalf) carries the deny
			// reason. For the draft we go a step further: we replace
			// the tool_use with a text block describing the verdict so
			// the model immediately sees why it can't proceed.
			//
			// Operators who need the model to retry can rewrite the
			// rule to HITL; deny is final.
			denyText := fmt.Sprintf(
				"Tool call %s was denied by clawpatrol: %s",
				hdr.Name, rule.Reason)
			newBlocks = append(newBlocks, mustJSON(map[string]any{
				"type": "text",
				"text": denyText,
			}))

		case rule.Verdict == VerdictHITL:
			rewrote = true
			pc := store.Park(hdr.ID, hdr.Name, []byte(argsJSON), rule.Reason)
			outcome.Parked = append(outcome.Parked, pc)
			outcome.Notes = append(outcome.Notes,
				fmt.Sprintf("hitl tool_use name=%q rule=%q token=%s",
					hdr.Name, rule.Name, pc.Token))
			// Drop the parked tool_use. The agent must never see it — the
			// model picks a polling tool via the gateway-initiated
			// follow-up below. Emit a "pending approval" text block as the
			// fallback the agent sees if the follow-up is unavailable or
			// fails; on follow-up success the whole body is replaced.
			newBlocks = append(newBlocks, mustJSON(map[string]any{
				"type": "text",
				"text": fmt.Sprintf(
					"Tool call %s requires human approval (clawpatrol). It is parked "+
						"and pending (token %s); it cannot run until approved.",
					hdr.Name, pc.Token),
			}))
		}
	}

	if !rewrote {
		return GateOutcome{Body: body, ToolUsesSeen: outcome.ToolUsesSeen}, nil
	}

	// HITL: run the gateway-initiated follow-up so the model chooses a
	// polling tool from the agent's own tools. On success, forward that
	// response verbatim — it is a real Anthropic turn naming a tool the
	// agent actually has. On failure, fall through to the pending-approval
	// text-block rewrite assembled above (the original tool call is
	// already removed, so nothing leaks).
	if len(outcome.Parked) > 0 {
		if fr, err := runFollowup(ctx, fc, body, outcome.Parked); err == nil {
			name, _, _, isTool := firstAgentBlock(fr)
			if isTool {
				outcome.Notes = append(outcome.Notes,
					fmt.Sprintf("hitl follow-up chose tool=%q", name))
			} else {
				outcome.Notes = append(outcome.Notes, "hitl follow-up returned no tool_use")
			}
			outcome.Body = fr
			outcome.Rewrote = true
			return outcome, nil
		} else if !errors.Is(err, errNoFollowupCaller) {
			outcome.Notes = append(outcome.Notes, "hitl follow-up failed: "+err.Error())
		}
	}

	newContent, err := json.Marshal(newBlocks)
	if err != nil {
		return GateOutcome{Body: body}, fmt.Errorf("anthropic content marshal: %w", err)
	}
	raw["content"] = newContent
	// stop_reason: this fall-through path only runs for deny (and the
	// HITL fallback when the follow-up was unavailable/failed); both
	// replace tool_use blocks with text. If no tool_use survives,
	// upstream's "tool_use" stop_reason no longer matches the content
	// shape — set "end_turn" so the agent finishes the turn cleanly.
	// (The HITL follow-up success path returns earlier with the model's
	// own response, whose stop_reason is already correct.)
	if _, present := raw["stop_reason"]; present {
		hasToolUse := false
		for _, b := range newBlocks {
			var h anthropicBlock
			if json.Unmarshal(b, &h) == nil && h.Type == "tool_use" {
				hasToolUse = true
				break
			}
		}
		if !hasToolUse {
			raw["stop_reason"] = mustJSON("end_turn")
		}
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return GateOutcome{Body: body}, fmt.Errorf("anthropic body marshal: %w", err)
	}
	outcome.Body = out
	outcome.Rewrote = true
	return outcome, nil
}

// mustJSON marshals an arbitrary value, panicking on error. Used for
// internal map / string literals whose shapes are known to be JSON-
// safe; the alternative is decorating every callsite with an unreachable
// error branch.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("toolgate: marshal: %v", err))
	}
	return b
}
