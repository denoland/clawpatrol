package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// demoSMTP is a synthetic ESMTP-ish protocol — TLS-terminated by the
// gateway, then a line-oriented command/response handshake handled
// entirely inside the plugin. No upstream involvement: the plugin
// is the "server". Demonstrates the TLS-but-not-HTTPS endpoint slot.
//
// AUTH PLAIN compares against the credential's secret material so
// only the right token clears the auth gate.
func demoSMTPDef() pluginsdk.EndpointDef {
	return pluginsdk.EndpointDef{
		TypeName:    "demo_smtp",
		Family:      "stream",
		TLSMode:     pluginsdk.TLSTerminate,
		RequiresVIP: true,
		Schema:      pluginsdk.Schema{},
		HandleConn:  handleDemoSMTP,
	}
}

func handleDemoSMTP(_ context.Context, conn *pluginsdk.Conn) error {
	expected := string(conn.CredentialSecret)

	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "220 demo ESMTP plugin-example ready\r\n"); err != nil {
		return err
	}

	authed := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		cmd := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(cmd)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			conn.Emit(pluginsdk.ConnEvent{Action: "allow", Verb: "EHLO", Summary: cmd})
			if _, err := io.WriteString(conn, "250-demo Hello\r\n250 AUTH PLAIN\r\n"); err != nil {
				return err
			}
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			tok := strings.TrimSpace(cmd[len("AUTH PLAIN"):])
			user, pass := decodeAuthPlain(tok)
			if pass == expected {
				authed = true
				conn.Emit(pluginsdk.ConnEvent{Action: "allow", Verb: "AUTH", Summary: "AUTH PLAIN " + user})
				if _, err := io.WriteString(conn, "235 2.7.0 Authentication successful\r\n"); err != nil {
					return err
				}
			} else {
				conn.Emit(pluginsdk.ConnEvent{Action: "deny", Verb: "AUTH", Reason: "bad token", Summary: "AUTH PLAIN " + user})
				if _, err := io.WriteString(conn, "535 5.7.8 Authentication credentials invalid\r\n"); err != nil {
					return err
				}
			}
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"), strings.HasPrefix(upper, "DATA"):
			if !authed {
				if _, err := io.WriteString(conn, "530 5.7.0 Authentication required\r\n"); err != nil {
					return err
				}
				continue
			}
			conn.Emit(pluginsdk.ConnEvent{Action: "allow", Verb: strings.SplitN(upper, " ", 2)[0], Summary: cmd})
			if _, err := io.WriteString(conn, "250 OK\r\n"); err != nil {
				return err
			}
		case strings.HasPrefix(upper, "QUIT"):
			conn.Emit(pluginsdk.ConnEvent{Action: "allow", Verb: "QUIT"})
			_, _ = io.WriteString(conn, "221 Bye\r\n")
			return nil
		default:
			conn.Emit(pluginsdk.ConnEvent{Action: "deny", Verb: "?", Reason: "unknown command", Summary: cmd})
			if _, err := fmt.Fprintf(conn, "500 5.5.1 Unknown command %q\r\n", cmd); err != nil {
				return err
			}
		}
	}
}

// decodeAuthPlain implements RFC 4616: \0 user \0 password (base64).
func decodeAuthPlain(b64 string) (user, pass string) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", ""
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 {
		return "", ""
	}
	return parts[1], parts[2]
}
