package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

var hclStartPos = hcl.Pos{Line: 1, Column: 1, Byte: 0}

// readDeviceBlockHCL extracts the raw HCL of the `device "<ip>" {}`
// block from the gateway config file. Returns an empty stub when the
// device has no block declared yet so the dashboard editor can render
// a blank starter.
func readDeviceBlockHCL(cfgPath, ip string) (string, error) {
	src, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", err
	}
	f, diags := hclwrite.ParseConfig(src, cfgPath, hclStartPos)
	if diags.HasErrors() {
		return "", fmt.Errorf("parse: %s", diags.Error())
	}
	for _, b := range f.Body().Blocks() {
		if b.Type() != "device" {
			continue
		}
		labels := b.Labels()
		if len(labels) == 1 && labels[0] == ip {
			out := hclwrite.NewEmptyFile()
			out.Body().AppendBlock(b)
			return string(out.Bytes()), nil
		}
	}
	// No block yet — return a starter the operator can fill in.
	return fmt.Sprintf("device %q {\n  # rule \"http_rule\" \"example\" {\n  #   endpoint = some-endpoint\n  #   match    = { method = \"POST\" }\n  #   verdict  = \"deny\"\n  # }\n}\n", ip), nil
}

// allowedDeviceFragmentKinds are the top-level block kinds the device
// editor accepts. The device block itself is required (and must label
// to the device's IP). Endpoint / credential / approver / policy are
// allowed so AI-generated edits can introduce a new endpoint when
// the operator says "block GET to deno.com" — the AI emits both the
// new endpoint block and the device block referencing it.
//
// Profile / rule / defaults blocks are deliberately disallowed —
// those belong to the global editor.
var allowedDeviceFragmentKinds = map[string]bool{
	"device":     true,
	"endpoint":   true,
	"credential": true,
	"approver":   true,
	"policy":     true,
}

// spliceDeviceBlockHCL replaces (or inserts) the operator's device
// fragment into gateway.hcl. The fragment is REQUIRED to include the
// `device "<ip>" {}` block, and may include endpoint / credential /
// approver / policy blocks that the device rules need to reference.
// Each block in the fragment replaces an existing same-(kind, name)
// block in gateway.hcl, or is appended at the end when none exists.
//
// An empty fragment removes the device block entirely (operator cleared
// the editor).
func spliceDeviceBlockHCL(cfgPath, ip, body string) ([]byte, error) {
	src, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	f, diags := hclwrite.ParseConfig(src, cfgPath, hclStartPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse current gateway.hcl: %s", diags.Error())
	}

	body = strings.TrimSpace(body)
	if body == "" {
		// Operator cleared the editor → drop the device block, leave
		// any endpoints / credentials it depended on in place.
		for _, b := range f.Body().Blocks() {
			if b.Type() == "device" && len(b.Labels()) == 1 && b.Labels()[0] == ip {
				f.Body().RemoveBlock(b)
			}
		}
		return f.Bytes(), nil
	}

	// Parse + validate the fragment shape.
	parser := hclparse.NewParser()
	if _, fdiags := parser.ParseHCL([]byte(body), "device.hcl"); fdiags.HasErrors() {
		return nil, fmt.Errorf("device fragment: %s", fdiags.Error())
	}
	wfrag, wdiags := hclwrite.ParseConfig([]byte(body), "device.hcl", hclStartPos)
	if wdiags.HasErrors() {
		return nil, fmt.Errorf("device fragment: %s", wdiags.Error())
	}

	deviceBlocks := 0
	for _, b := range wfrag.Body().Blocks() {
		kind := b.Type()
		if !allowedDeviceFragmentKinds[kind] {
			return nil, fmt.Errorf("device fragment: %q blocks aren't allowed here — edit the global gateway.hcl for that", kind)
		}
		if kind == "device" {
			labels := b.Labels()
			if len(labels) != 1 || labels[0] != ip {
				return nil, fmt.Errorf("device fragment: device label must be %q, got %v", ip, labels)
			}
			deviceBlocks++
		}
	}
	if deviceBlocks == 0 {
		return nil, fmt.Errorf("device fragment: missing `device %q { ... }` block", ip)
	}
	if deviceBlocks > 1 {
		return nil, fmt.Errorf("device fragment: multiple device blocks for %q — only one allowed", ip)
	}

	// For each block in the fragment, drop any same-(kind, labels)
	// block already in gateway.hcl. Then append every fragment block
	// at the end. Order: endpoints/credentials/approvers/policies
	// first so a device block referencing them lands AFTER its deps.
	type bk struct {
		kind   string
		labels string
	}
	keyOf := func(b *hclwrite.Block) bk {
		return bk{kind: b.Type(), labels: strings.Join(b.Labels(), "\x00")}
	}
	want := map[bk]bool{}
	var depBlocks, deviceBlock []*hclwrite.Block
	for _, b := range wfrag.Body().Blocks() {
		want[keyOf(b)] = true
		if b.Type() == "device" {
			deviceBlock = append(deviceBlock, b)
		} else {
			depBlocks = append(depBlocks, b)
		}
	}
	for _, b := range f.Body().Blocks() {
		if want[keyOf(b)] {
			f.Body().RemoveBlock(b)
		}
	}

	var out bytes.Buffer
	out.Write(bytes.TrimRight(f.Bytes(), "\n"))
	out.WriteString("\n")
	for _, b := range depBlocks {
		out.WriteString("\n")
		out.Write(bytes.TrimSpace(blockBytes(b)))
		out.WriteString("\n")
	}
	for _, b := range deviceBlock {
		out.WriteString("\n")
		out.Write(bytes.TrimSpace(blockBytes(b)))
		out.WriteString("\n")
	}
	return out.Bytes(), nil
}

// blockBytes serializes one block by appending it to a fresh
// hclwrite.File and reading the bytes back. hclwrite doesn't expose a
// per-block Bytes() method directly.
func blockBytes(b *hclwrite.Block) []byte {
	out := hclwrite.NewEmptyFile()
	out.Body().AppendBlock(b)
	return out.Bytes()
}
