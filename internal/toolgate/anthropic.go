package toolgate

// Anthropic /v1/messages response gating. Parses tool_use blocks out
// of the response body, applies the rule set, and rewrites the
// response shape according to the verdict — either synthesising a
// matching tool_result for deny / approve-skipped paths, or swapping
// the tool_use for a polling-tool tool_use the agent will execute
// against clawpatrol's own /api/approval/poll endpoint.
//
// Only non-streaming JSON responses are handled here. Streaming SSE
// is the obvious follow-up — the same parser shape applies block by
// block, but the rewrite needs to coordinate with the SSE event
// frame so the agent's incremental decoder stays consistent.

import (
	"encoding/json"
	"fmt"
)

// PollingToolName is the tool clawpatrol injects into the rewritten
// response so the agent will call back on the approval endpoint. The
// draft picks the long-poll variant unconditionally — see
// doc/tool-call-gating.md for why and the v2 plan to introspect the
// agent's available tools instead.
const PollingToolName = "clawpatrol_poll"

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
func GateAnthropicResponse(rules RuleSet, store *Store, body []byte) (GateOutcome, error) {
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
			// Replace with a polling tool_use the agent will execute.
			// The polling tool's input carries the opaque token plus
			// a hint about the original tool so debug tools (and the
			// model's own context) can describe what's pending.
			pollInput := map[string]any{
				"token":            pc.Token,
				"original_tool":    hdr.Name,
				"original_tool_id": hdr.ID,
			}
			newBlocks = append(newBlocks, mustJSON(map[string]any{
				"type":  "tool_use",
				"id":    "toolu_poll_" + pc.Token[:16],
				"name":  PollingToolName,
				"input": pollInput,
			}))
		}
	}

	if !rewrote {
		return GateOutcome{Body: body, ToolUsesSeen: outcome.ToolUsesSeen}, nil
	}

	newContent, err := json.Marshal(newBlocks)
	if err != nil {
		return GateOutcome{Body: body}, fmt.Errorf("anthropic content marshal: %w", err)
	}
	raw["content"] = newContent
	// stop_reason: if we replaced the only tool_use with a text block
	// (deny), upstream's "tool_use" stop_reason no longer matches the
	// content shape. Set "end_turn" so the agent finishes the turn
	// cleanly. For HITL we keep "tool_use" — there IS still a tool_use
	// in the content, just a different one.
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
