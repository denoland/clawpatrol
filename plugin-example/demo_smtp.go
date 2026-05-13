package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// demoSMTP is a synthetic ESMTP-ish protocol — TLS-terminated by the
// gateway, then a line-oriented command/response handshake that
// asks the gateway for an allow/deny verdict on every command via
// Conn.Evaluate. No upstream involvement.
//
// The plugin doesn't make policy decisions itself: each command
// builds an `smtp` facet payload (verb, auth_user, mail_from,
// rcpt_to) and the gateway's compiled rules (CEL conditions
// against `smtp.verb` etc.) return the verdict. AUTH PLAIN still
// compares the password against the credential's secret before
// asking the gateway, since password verification is a protocol
// check, not a policy check.
func demoSMTPDef() pluginsdk.EndpointDef {
	return pluginsdk.EndpointDef{
		TypeName:    "demo_smtp",
		Family:      "smtp", // SDK auto-namespaces to "example.smtp"
		TLSMode:     pluginsdk.TLSTerminate,
		RequiresVIP: true,
		Schema:      pluginsdk.Schema{},
		HandleConn:  handleDemoSMTP,
	}
}

// smtpSession threads per-conn state into each Evaluate call so the
// facet payload reflects the running command stream (auth_user
// stays set after AUTH; rcpt_to accumulates across multiple
// RCPT lines).
type smtpSession struct {
	authUser string
	mailFrom string
	rcptTo   []string
}

func handleDemoSMTP(ctx context.Context, conn *pluginsdk.Conn) error {
	expectedPassword := string(conn.CredentialSecret)
	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "220 demo ESMTP plugin-example ready\r\n"); err != nil {
		return err
	}

	s := &smtpSession{}
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
		verb := strings.SplitN(upper, " ", 2)[0]

		// AUTH PLAIN: verify password first (protocol check), then
		// ask the gateway whether *this* authenticated user is
		// allowed to proceed.
		if strings.HasPrefix(upper, "AUTH PLAIN") {
			tok := strings.TrimSpace(cmd[len("AUTH PLAIN"):])
			user, pass := decodeAuthPlain(tok)
			if pass != expectedPassword {
				if _, err := io.WriteString(conn, "535 5.7.8 Authentication credentials invalid\r\n"); err != nil {
					return err
				}
				continue
			}
			s.authUser = user
		}

		// MAIL FROM / RCPT TO: track session state for the facet
		// payload so rules can reason about cumulative recipients.
		switch verb {
		case "MAIL":
			s.mailFrom = parseAddress(cmd[4:])
		case "RCPT":
			if addr := parseAddress(cmd[4:]); addr != "" {
				s.rcptTo = append(s.rcptTo, addr)
			}
		}

		action := map[string]any{
			"verb":      verb,
			"auth_user": s.authUser,
			"mail_from": s.mailFrom,
			"rcpt_to":   s.rcptTo,
		}
		v, err := conn.Evaluate(ctx, "smtp", action, cmd)
		if err != nil {
			return fmt.Errorf("evaluate %q: %w", cmd, err)
		}

		// Map gateway verdict onto an SMTP response code.
		resp := smtpReplyFor(verb, v)
		if _, err := io.WriteString(conn, resp); err != nil {
			return err
		}

		// DATA opens a separate body upload phase: reply 354, read
		// lines until "\r\n.\r\n", then re-Evaluate with the body as
		// a stream so the gateway can pull it (fully if a rule
		// references smtp.body, otherwise just a log-prefix).
		if verb == "DATA" && (v.Action == "allow" || v.Action == "hitl_allow") {
			if _, err := io.WriteString(conn, "354 End data with <CR><LF>.<CR><LF>\r\n"); err != nil {
				return err
			}
			body, derr := readSMTPData(br)
			if derr != nil {
				return derr
			}
			bodyAction := map[string]any{
				"verb":      "BODY",
				"auth_user": s.authUser,
				"mail_from": s.mailFrom,
				"rcpt_to":   s.rcptTo,
				"body":      pluginsdk.Stream(bytes.NewReader(body)),
			}
			bv, err := conn.Evaluate(ctx, "smtp", bodyAction, fmt.Sprintf("BODY (%d bytes)", len(body)))
			if err != nil {
				return fmt.Errorf("evaluate body: %w", err)
			}
			if _, err := io.WriteString(conn, smtpReplyFor("BODY", bv)); err != nil {
				return err
			}
		}

		if verb == "QUIT" {
			return nil
		}
	}
}

// readSMTPData drains the message body that follows DATA, stopping
// at the SMTP terminator "\r\n.\r\n". Strips the dot-stuffing and
// returns just the message bytes.
func readSMTPData(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return buf.Bytes(), err
		}
		stripped := strings.TrimRight(line, "\r\n")
		if stripped == "." {
			return buf.Bytes(), nil
		}
		// RFC 5321: leading "." on a line is an escape for a line
		// that actually starts with a dot.
		if strings.HasPrefix(stripped, ".") {
			stripped = stripped[1:]
		}
		buf.WriteString(stripped)
		buf.WriteString("\r\n")
	}
}

func smtpReplyFor(verb string, v pluginsdk.Verdict) string {
	switch v.Action {
	case "allow", "hitl_allow":
		switch verb {
		case "EHLO", "HELO":
			return "250-demo Hello\r\n250 AUTH PLAIN\r\n"
		case "AUTH":
			return "235 2.7.0 Authentication successful\r\n"
		case "QUIT":
			return "221 Bye\r\n"
		case "BODY":
			return "250 2.0.0 Ok: queued\r\n"
		default:
			return "250 OK\r\n"
		}
	default:
		reason := v.Reason
		if reason == "" {
			reason = "policy denied"
		}
		// 5xx-class permanent failure.
		if verb == "AUTH" {
			return fmt.Sprintf("535 5.7.8 %s\r\n", reason)
		}
		return fmt.Sprintf("550 5.7.1 %s\r\n", reason)
	}
}

// parseAddress pulls the address out of `MAIL FROM:<alice@example.com>`
// (or RCPT TO equivalents). Returns "" when malformed; the gateway
// rule sees the empty string and presumably denies.
func parseAddress(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
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
