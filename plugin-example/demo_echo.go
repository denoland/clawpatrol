package main

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// demoEcho is the simplest of the three: plain TCP, no TLS. The
// gateway hands the raw agent connection to the plugin; the plugin
// reads lines and writes them back prefixed with the credential's
// secret value. Demonstrates the non-TLS endpoint slot.
func demoEchoDef() pluginsdk.EndpointDef {
	return pluginsdk.EndpointDef{
		TypeName:    "demo_echo",
		Family:      "stream",
		TLSMode:     pluginsdk.TLSNone,
		RequiresVIP: true,
		Schema:      pluginsdk.Schema{},
		HandleConn:  handleDemoEcho,
	}
}

func handleDemoEcho(_ context.Context, conn *pluginsdk.Conn) error {
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
		conn.Emit(pluginsdk.ConnEvent{Action: "allow", Verb: "echo", Summary: line[:len(line)-1]})
		if _, err := fmt.Fprintf(conn, "%s: %s", prefix, line); err != nil {
			return err
		}
	}
}
