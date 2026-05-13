package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// demoEcho is a plain-TCP echo endpoint. The gateway hands the raw
// agent connection to the plugin; the plugin reads lines, asks the
// gateway for a verdict via the `echo` facet, and either echoes the
// line back (prefixed with the credential's secret) or replies with
// a deny message. The gateway does the logging.
func demoEchoDef() pluginsdk.EndpointDef {
	return pluginsdk.EndpointDef{
		TypeName:    "demo_echo",
		Family:      "echo", // SDK auto-namespaces to "example.echo"
		TLSMode:     pluginsdk.TLSNone,
		RequiresVIP: true,
		Schema:      pluginsdk.Schema{},
		HandleConn:  handleDemoEcho,
	}
}

func handleDemoEcho(ctx context.Context, conn *pluginsdk.Conn) error {
	prefix := string(conn.CredentialSecret)
	if prefix == "" {
		prefix = "echo"
	}
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		clean := strings.TrimRight(line, "\r\n")
		v, err := conn.Evaluate(ctx, "echo", map[string]any{"line": clean}, clean)
		if err != nil {
			return fmt.Errorf("evaluate %q: %w", clean, err)
		}
		switch v.Action {
		case "allow", "hitl_allow":
			if _, err := fmt.Fprintf(conn, "%s: %s\n", prefix, clean); err != nil {
				return err
			}
		default:
			reason := v.Reason
			if reason == "" {
				reason = "denied"
			}
			if _, err := fmt.Fprintf(conn, "DENY: %s\n", reason); err != nil {
				return err
			}
		}
	}
}
