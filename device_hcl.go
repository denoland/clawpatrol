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

// spliceDeviceBlockHCL replaces (or inserts) the `device "<ip>" {}`
// block in gateway.hcl with the operator-edited body. Returns the
// merged file bytes — caller validates + persists.
//
// The body parameter is expected to start with `device "<ip>" {` so
// the dashboard editor's textarea contents drop in verbatim. An empty
// body removes the block entirely.
func spliceDeviceBlockHCL(cfgPath, ip, body string) ([]byte, error) {
	src, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	f, diags := hclwrite.ParseConfig(src, cfgPath, hclStartPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse current gateway.hcl: %s", diags.Error())
	}

	// Drop any existing block for this IP.
	for _, b := range f.Body().Blocks() {
		if b.Type() != "device" {
			continue
		}
		labels := b.Labels()
		if len(labels) == 1 && labels[0] == ip {
			f.Body().RemoveBlock(b)
		}
	}

	body = strings.TrimSpace(body)
	if body == "" {
		// Operator cleared the editor → block stays removed.
		return f.Bytes(), nil
	}

	// Parse the operator-supplied body as a standalone HCL fragment
	// and confirm it contains exactly one `device "<ip>" {}` block
	// for the right IP. This prevents a typo in the editor from
	// silently dropping the block while leaving the operator's
	// changes lost.
	parser := hclparse.NewParser()
	frag, fdiags := parser.ParseHCL([]byte(body), "device.hcl")
	if fdiags.HasErrors() {
		return nil, fmt.Errorf("device block: %s", fdiags.Error())
	}
	wfrag, wdiags := hclwrite.ParseConfig([]byte(body), "device.hcl", hclStartPos)
	if wdiags.HasErrors() {
		return nil, fmt.Errorf("device block: %s", wdiags.Error())
	}
	_ = frag
	count := 0
	for _, b := range wfrag.Body().Blocks() {
		if b.Type() != "device" {
			return nil, fmt.Errorf("device block: only `device %q { ... }` blocks allowed in this editor", ip)
		}
		labels := b.Labels()
		if len(labels) != 1 || labels[0] != ip {
			return nil, fmt.Errorf("device block: label must be %q, got %v", ip, labels)
		}
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("device block: no `device %q { ... }` block found", ip)
	}
	if count > 1 {
		return nil, fmt.Errorf("device block: multiple device blocks for %q — only one allowed", ip)
	}

	// Append the new block to the end of gateway.hcl, separated by a
	// blank line for readability. (hclwrite's RemoveBlock leaves
	// whitespace as-is; trim trailing blank runs to stay tidy.)
	var out bytes.Buffer
	out.Write(bytes.TrimRight(f.Bytes(), "\n"))
	out.WriteString("\n\n")
	out.Write(bytes.TrimSpace(wfrag.Bytes()))
	out.WriteString("\n")
	return out.Bytes(), nil
}
