package toolgate

// Streaming (SSE) variant of the Anthropic /v1/messages response gate.
//
// Anthropic's streaming API delivers a tool_use block incrementally:
//
//	event: content_block_start
//	data: {"type":"content_block_start","index":1,
//	       "content_block":{"type":"tool_use","id":"toolu_…","name":"bash","input":{}}}
//	event: content_block_delta
//	data: {"type":"content_block_delta","index":1,
//	       "delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}
//	…more input_json_delta frames…
//	event: content_block_stop
//	data: {"type":"content_block_stop","index":1}
//	event: message_delta
//	data: {"type":"message_delta","delta":{"stop_reason":"tool_use",…},"usage":{…}}
//
// The verdict needs the *complete* tool_use (name + full input JSON),
// which isn't known until content_block_stop. So this implements the
// "per-block buffering" shape (approach 2 in the PR discussion): non-
// tool_use frames (message_start, text blocks, ping, usage) stream
// straight through to preserve time-to-first-token, while a tool_use
// block's frames are HELD from content_block_start until
// content_block_stop. At stop we know the full input, evaluate the
// rule set, and emit one of:
//
//   - allow / unmatched: replay the held frames verbatim.
//   - deny: drop the tool_use; emit a text block carrying the reason.
//   - hitl: drop the tool_use; park the call and emit a clawpatrol_poll
//     tool_use frame sequence the agent will execute.
//
// stop_reason is rewritten "tool_use" → "end_turn" in the trailing
// message_delta iff every tool_use in the turn was denied/blocked (no
// tool_use survives in the output), mirroring the non-streaming path.
//
// FAIL CLOSED. Unlike the JSON path (which forwards the original body
// on a parse error), the stream gate never forwards a tool_use it
// could not evaluate. Anything that prevents a clean verdict — an
// unparseable content_block_start, a malformed delta on a held block,
// an oversized input, a stream that ends mid-block — results in the
// tool_use being blocked (replaced with a refusal text block) or the
// stream being terminated, never in the raw tool_use reaching the
// agent. A held tool_use's frames are only ever emitted after a
// successful allow verdict.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// maxToolInputBytes caps the accumulated input_json_delta payload for a
// single tool_use block. A block whose input exceeds this is treated as
// an evaluation failure and blocked — never forwarded raw. Mirrors the
// 8MB MaxBytesReader cap on the non-streaming JSON path.
const maxToolInputBytes = 8 << 20

// SSEOutcome accumulates the side effects of a streamed gating pass:
// parked HITL calls and human-readable notes for the dashboard event
// row. Unlike GateOutcome it carries no Body — the rewrite is streamed
// to the destination writer as it happens.
type SSEOutcome struct {
	Parked       []*PendingCall
	Notes        []string
	ToolUsesSeen int
	// Rewrote reports whether any frame was altered (deny / hitl / block
	// / stop_reason flip). False means the stream passed through
	// byte-for-byte.
	Rewrote bool
}

// GateAnthropicSSE reads an Anthropic /v1/messages SSE stream from src,
// applies the rule set block by block, and writes the (possibly
// rewritten) stream to dst. It returns a non-nil error only on a
// condition that forces the stream to fail closed (an unparseable
// content_block_start, a protocol violation, a truncated tool_use, or
// a write/read failure); callers should propagate it so the client
// connection breaks rather than receive an ungated tail.
func GateAnthropicSSE(rules RuleSet, store *Store, src io.Reader, dst io.Writer, out *SSEOutcome) error {
	if out == nil {
		out = &SSEOutcome{}
	}
	br := bufio.NewReader(src)

	// Per-block buffer. Anthropic streams content blocks strictly one at
	// a time (block i fully start→delta…→stop before i+1 opens), so a
	// single open-block slot suffices.
	type blockState struct {
		active  bool
		index   int
		id      string
		name    string
		input   bytes.Buffer // accumulated input_json_delta partials
		heldRaw [][]byte     // every frame between start and stop (deltas,
		//                       interleaved pings, …), replayed verbatim on
		//                       allow so the stream is byte-identical.
		startRaw []byte // raw content_block_start frame
		errored  bool   // cannot evaluate → fail closed at stop
	}
	var blk blockState
	emittedToolUse := false

	// Current event being assembled: rawEvent is the verbatim bytes
	// (every line incl. the terminating blank), dataBuf the concatenated
	// `data:` payload used for parsing.
	var rawEvent bytes.Buffer
	var dataBuf bytes.Buffer

	resetEvent := func() {
		rawEvent.Reset()
		dataBuf.Reset()
	}

	// bufferHeld appends a verbatim frame to the held block's replay list
	// (skipped once the block has errored — those frames are discarded
	// since the block will be blocked, not replayed).
	bufferHeld := func(b *blockState, raw []byte) {
		if !b.errored {
			b.heldRaw = append(b.heldRaw, raw)
		}
	}

	// flushBlock evaluates the held tool_use block and emits its
	// replacement (or replays it). stopRaw is the verbatim
	// content_block_stop frame, replayed on the allow path.
	flushBlock := func(stopRaw []byte) error {
		held := blk
		blk = blockState{}
		argsJSON := held.input.String()
		if argsJSON == "" {
			// No input_json_delta frames → the tool_use input is the `{}`
			// placeholder from content_block_start.
			argsJSON = "{}"
		}

		if held.errored {
			// Fail closed: we could not faithfully reconstruct or evaluate
			// this tool call, so it must not reach the agent. Replace it
			// with a refusal text block.
			out.Rewrote = true
			out.Notes = append(out.Notes,
				fmt.Sprintf("blocked tool_use name=%q reason=eval-error", held.name))
			return emitDenyTextBlock(dst, held.index, fmt.Sprintf(
				"Tool call %s was blocked by clawpatrol: the gateway could not evaluate it for policy.",
				held.name))
		}

		rule, matched := rules.Evaluate(held.name, argsJSON)
		switch {
		case !matched, rule.Verdict == VerdictAllow:
			// Replay the held frames verbatim: start, everything held in
			// between (deltas + interleaved pings), stop.
			if _, err := dst.Write(held.startRaw); err != nil {
				return err
			}
			for _, d := range held.heldRaw {
				if _, err := dst.Write(d); err != nil {
					return err
				}
			}
			if _, err := dst.Write(stopRaw); err != nil {
				return err
			}
			emittedToolUse = true
			return nil

		case rule.Verdict == VerdictDeny:
			out.Rewrote = true
			out.Notes = append(out.Notes,
				fmt.Sprintf("deny tool_use name=%q rule=%q reason=%q",
					held.name, rule.Name, rule.Reason))
			return emitDenyTextBlock(dst, held.index, fmt.Sprintf(
				"Tool call %s was denied by clawpatrol: %s", held.name, rule.Reason))

		case rule.Verdict == VerdictHITL:
			out.Rewrote = true
			pc := store.Park(held.id, held.name, []byte(argsJSON), rule.Reason)
			out.Parked = append(out.Parked, pc)
			out.Notes = append(out.Notes,
				fmt.Sprintf("hitl tool_use name=%q rule=%q token=%s",
					held.name, rule.Name, pc.Token))
			// A clawpatrol_poll tool_use IS still a tool_use in the output,
			// so stop_reason stays "tool_use".
			emittedToolUse = true
			return emitPollBlock(dst, held.index, pc)
		}
		return nil
	}

	// dispatch handles one fully-assembled SSE event.
	dispatch := func() error {
		raw := append([]byte(nil), rawEvent.Bytes()...)
		data := append([]byte(nil), dataBuf.Bytes()...)
		resetEvent()

		if len(bytes.TrimSpace(raw)) == 0 {
			return nil // stray blank line
		}
		// Comment-only / data-less frames carry no tool_use; pass through.
		if len(bytes.TrimSpace(data)) == 0 {
			_, err := dst.Write(raw)
			return err
		}

		var hdr struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
		}
		if err := json.Unmarshal(data, &hdr); err != nil {
			// Unparseable frame. If we're holding a tool_use block this
			// could be one of its delta/stop frames — mark errored and let
			// the stop handler fail it closed. Otherwise an unparseable
			// frame could be a content_block_start announcing a tool_use we
			// would leak by passing through, so fail closed hard.
			if blk.active {
				blk.errored = true
				return nil
			}
			return fmt.Errorf("toolgate sse: unparseable event frame: %w", err)
		}

		// While a tool_use block is held, every frame is buffered (or
		// concludes the block) — nothing streams through, so an allow
		// replay is byte-identical to upstream including interleaved
		// pings.
		if blk.active {
			switch hdr.Type {
			case "content_block_start":
				return fmt.Errorf("toolgate sse: content_block_start (index %d) while block %d still open",
					hdr.Index, blk.index)
			case "content_block_stop":
				if hdr.Index != blk.index {
					return fmt.Errorf("toolgate sse: content_block_stop index %d, expected held block %d",
						hdr.Index, blk.index)
				}
				return flushBlock(raw)
			case "content_block_delta":
				if hdr.Index == blk.index {
					var ev struct {
						Delta struct {
							Type        string `json:"type"`
							PartialJSON string `json:"partial_json"`
						} `json:"delta"`
					}
					if err := json.Unmarshal(data, &ev); err != nil {
						blk.errored = true
						return nil
					}
					if ev.Delta.Type == "input_json_delta" {
						blk.input.WriteString(ev.Delta.PartialJSON)
						if blk.input.Len() > maxToolInputBytes {
							// Oversized: stop accumulating, drop replay frames
							// to bound memory, fail closed at stop.
							blk.errored = true
							blk.heldRaw = nil
							return nil
						}
					}
				}
				bufferHeld(&blk, raw)
				return nil
			default:
				// ping / message-level frames interleaved mid-block: hold
				// them so allow-path order is preserved.
				bufferHeld(&blk, raw)
				return nil
			}
		}

		switch hdr.Type {
		case "content_block_start":
			var ev struct {
				Index        int `json:"index"`
				ContentBlock struct {
					Type string `json:"type"`
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"content_block"`
			}
			if err := json.Unmarshal(data, &ev); err != nil {
				// A content_block_start we can't parse might announce a
				// tool_use; fail closed rather than forward it.
				return fmt.Errorf("toolgate sse: content_block_start parse: %w", err)
			}
			if ev.ContentBlock.Type == "tool_use" {
				out.ToolUsesSeen++
				// Hold the block; accumulate input from the deltas only —
				// the start frame's input is the `{}` placeholder.
				blk = blockState{
					active:   true,
					index:    ev.Index,
					id:       ev.ContentBlock.ID,
					name:     ev.ContentBlock.Name,
					startRaw: raw,
				}
				return nil
			}
			// text / thinking / other block: stream through immediately.
			_, err := dst.Write(raw)
			return err

		case "message_delta":
			return maybeRewriteStopReason(dst, raw, data, emittedToolUse, out)

		default:
			// content_block_delta / content_block_stop for a non-held
			// (text) block, message_start, message_stop, ping, error, and
			// any future frame type: no held tool_use payload, stream
			// through.
			_, err := dst.Write(raw)
			return err
		}
	}

	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			rawEvent.Write(line)
			field := bytes.TrimRight(line, "\n")
			field = bytes.TrimRight(field, "\r")
			switch {
			case len(field) == 0:
				if derr := dispatch(); derr != nil {
					return derr
				}
			case bytes.HasPrefix(field, []byte("data:")):
				payload := bytes.TrimPrefix(field[len("data:"):], []byte(" "))
				if dataBuf.Len() > 0 {
					dataBuf.WriteByte('\n')
				}
				dataBuf.Write(payload)
				// `event:` and comment (`:`) lines are kept in rawEvent for
				// verbatim pass-through; dispatch keys off the data "type".
			}
		}
		if err != nil {
			if err == io.EOF {
				// Flush a trailing event that lacked a blank terminator.
				if rawEvent.Len() > 0 {
					if derr := dispatch(); derr != nil {
						return derr
					}
				}
				if blk.active {
					// Stream ended mid tool_use block: the verdict was never
					// applied. Fail closed — the held call is dropped (never
					// emitted) and we surface the truncation as an error.
					return fmt.Errorf("toolgate sse: stream ended mid tool_use block (index %d)", blk.index)
				}
				return nil
			}
			return err
		}
	}
}

// maybeRewriteStopReason passes a message_delta through unchanged unless
// the turn produced no surviving tool_use yet still reports
// stop_reason "tool_use" (every tool_use was denied/blocked). In that
// case it rewrites stop_reason to "end_turn" so the agent finishes the
// turn cleanly, preserving every other field (usage, stop_sequence).
func maybeRewriteStopReason(dst io.Writer, raw, data []byte, emittedToolUse bool, out *SSEOutcome) error {
	if emittedToolUse {
		_, err := dst.Write(raw)
		return err
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		_, werr := dst.Write(raw) // usage frame, no tool_use to leak
		return werr
	}
	deltaRaw, ok := msg["delta"]
	if !ok {
		_, err := dst.Write(raw)
		return err
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(deltaRaw, &delta); err != nil {
		_, werr := dst.Write(raw)
		return werr
	}
	sr, ok := delta["stop_reason"]
	if !ok {
		_, err := dst.Write(raw)
		return err
	}
	var srStr string
	if err := json.Unmarshal(sr, &srStr); err != nil || srStr != "tool_use" {
		_, werr := dst.Write(raw)
		return werr
	}
	delta["stop_reason"] = json.RawMessage(`"end_turn"`)
	newDelta, err := json.Marshal(delta)
	if err != nil {
		return fmt.Errorf("toolgate sse: stop_reason rewrite: %w", err)
	}
	msg["delta"] = newDelta
	newData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("toolgate sse: message_delta rewrite: %w", err)
	}
	out.Rewrote = true
	return writeSSEFrame(dst, "message_delta", json.RawMessage(newData))
}

// emitDenyTextBlock writes a complete text content block (start →
// text_delta → stop) at the given index carrying the refusal text.
func emitDenyTextBlock(dst io.Writer, index int, text string) error {
	if err := writeSSEMap(dst, "content_block_start", map[string]any{
		"type":          "content_block_start",
		"index":         index,
		"content_block": map[string]any{"type": "text", "text": ""},
	}); err != nil {
		return err
	}
	if err := writeSSEMap(dst, "content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}); err != nil {
		return err
	}
	return writeSSEMap(dst, "content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": index,
	})
}

// emitPollBlock writes a complete clawpatrol_poll tool_use block (start
// → input_json_delta → stop) at the given index, carrying the opaque
// token plus the original tool's identity. Shape matches the non-
// streaming path's polling tool_use.
func emitPollBlock(dst io.Writer, index int, pc *PendingCall) error {
	if err := writeSSEMap(dst, "content_block_start", map[string]any{
		"type":  "content_block_start",
		"index": index,
		"content_block": map[string]any{
			"type":  "tool_use",
			"id":    "toolu_poll_" + pc.Token[:16],
			"name":  PollingToolName,
			"input": map[string]any{},
		},
	}); err != nil {
		return err
	}
	pollInput, err := json.Marshal(map[string]any{
		"token":            pc.Token,
		"original_tool":    pc.ToolName,
		"original_tool_id": pc.ToolUseID,
	})
	if err != nil {
		return fmt.Errorf("toolgate sse: poll input marshal: %w", err)
	}
	if err := writeSSEMap(dst, "content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": string(pollInput)},
	}); err != nil {
		return err
	}
	return writeSSEMap(dst, "content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": index,
	})
}

// writeSSEMap marshals v to JSON and writes it as a single SSE event.
func writeSSEMap(dst io.Writer, event string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("toolgate sse: marshal %s: %w", event, err)
	}
	return writeSSEFrame(dst, event, b)
}

// writeSSEFrame writes a pre-serialised JSON payload as one SSE event
// (event line + data line + terminating blank line).
func writeSSEFrame(dst io.Writer, event string, data []byte) error {
	if _, err := fmt.Fprintf(dst, "event: %s\ndata: ", event); err != nil {
		return err
	}
	if _, err := dst.Write(data); err != nil {
		return err
	}
	_, err := dst.Write([]byte("\n\n"))
	return err
}
