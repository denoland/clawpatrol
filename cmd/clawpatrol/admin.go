package main

// Operator-side CLI shims for the dashboard mutation endpoints.
// These exist so an agent (or anyone scripting against the gateway)
// can drive approve / oauth-start / oauth-exchange without grepping
// source to learn the API shapes.
//
// Auth lives in the gateway's dashboardAuthGate. The simplest case
// is a tailnet operator on the dashboard_operators allowlist — the
// gateway resolves whois on the inbound HTTP connection. Off-tailnet
// callers can pass a session cookie via CLAWPATROL_DASHBOARD_COOKIE
// (or the existing browser-issued cookie if the same machine just
// logged in).

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// gatewayBaseURL pulls the gateway base URL from --gateway, then
// CLAWPATROL_GATEWAY, and errors otherwise. Trailing slashes get
// trimmed so callers can join paths with a plain "/api/...".
func gatewayBaseURL(fs *flag.FlagSet) (string, error) {
	gw := fs.Lookup("gateway").Value.String()
	if gw == "" {
		gw = os.Getenv("CLAWPATROL_GATEWAY")
	}
	if gw == "" {
		return "", errors.New("--gateway URL required (or set CLAWPATROL_GATEWAY)")
	}
	return strings.TrimRight(gw, "/"), nil
}

// postAdmin issues a POST against the gateway with optional JSON body
// and returns (status, raw response body). Adds the session cookie
// from CLAWPATROL_DASHBOARD_COOKIE when present.
func postAdmin(base, path string, body any) (int, []byte, error) {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(http.MethodPost, base+path, reqBody)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c := os.Getenv("CLAWPATROL_DASHBOARD_COOKIE"); c != "" {
		req.Header.Set("Cookie", c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, nil
}

// runApprove implements `clawpatrol approve [flags] <code>`.
func runApprove(args []string) {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	gw := fs.String("gateway", "", "gateway base URL (or env CLAWPATROL_GATEWAY)")
	profile := fs.String("profile", "", "profile to assign the device to (overrides the join-time suggestion)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: clawpatrol approve [flags] <code>

Approve a pending `+"`clawpatrol join`"+` device-code so the agent's
device is registered against the gateway.

flags:
  --gateway URL      gateway base URL (or env CLAWPATROL_GATEWAY)
  --profile NAME     profile to assign (overrides the join-time suggestion)`)
	}
	_ = fs.Parse(args)
	_ = gw // captured by gatewayBaseURL below
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	code := fs.Arg(0)
	base, err := gatewayBaseURL(fs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	q := url.Values{}
	q.Set("code", code)
	if *profile != "" {
		q.Set("profile", *profile)
	}
	status, body, err := postAdmin(base, "/api/onboard/approve?"+q.Encode(), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(body)
	if !bytes.HasSuffix(body, []byte("\n")) {
		fmt.Println()
	}
	if status >= 400 {
		os.Exit(1)
	}
}

// runOAuthStart implements `clawpatrol oauth-start [flags] <credential-id>`.
func runOAuthStart(args []string) {
	fs := flag.NewFlagSet("oauth-start", flag.ExitOnError)
	_ = fs.String("gateway", "", "gateway base URL (or env CLAWPATROL_GATEWAY)")
	extra := fs.String("extra-scopes", "", "comma-separated extra OAuth scopes to request")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: clawpatrol oauth-start [flags] <credential-id>

Begin an OAuth flow for the named credential. Prints a JSON object
containing auth_url and state. Open auth_url in a browser, complete
the consent, then feed the resulting code to `+"`clawpatrol oauth-exchange`"+`.

flags:
  --gateway URL          gateway base URL (or env CLAWPATROL_GATEWAY)
  --extra-scopes LIST    comma-separated extra OAuth scopes to request`)
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	id := fs.Arg(0)
	base, err := gatewayBaseURL(fs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	q := url.Values{}
	q.Set("id", id)
	if *extra != "" {
		q.Set("extra_scopes", *extra)
	}
	status, body, err := postAdmin(base, "/api/oauth/start?"+q.Encode(), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(body)
	if !bytes.HasSuffix(body, []byte("\n")) {
		fmt.Println()
	}
	if status >= 400 {
		os.Exit(1)
	}
}

// runOAuthExchange implements `clawpatrol oauth-exchange [flags] <state> <code>`.
func runOAuthExchange(args []string) {
	fs := flag.NewFlagSet("oauth-exchange", flag.ExitOnError)
	_ = fs.String("gateway", "", "gateway base URL (or env CLAWPATROL_GATEWAY)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: clawpatrol oauth-exchange [flags] <state> <code>

Exchange a one-time OAuth code for tokens. The state is the value
returned by `+"`clawpatrol oauth-start`"+`; the code is what the OAuth
provider showed the operator after the consent step.

flags:
  --gateway URL      gateway base URL (or env CLAWPATROL_GATEWAY)`)
	}
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}
	state, code := fs.Arg(0), fs.Arg(1)
	base, err := gatewayBaseURL(fs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	status, body, err := postAdmin(base, "/api/oauth/exchange",
		map[string]string{"state": state, "code": code})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(body)
	if !bytes.HasSuffix(body, []byte("\n")) {
		fmt.Println()
	}
	if status >= 400 {
		os.Exit(1)
	}
}
