package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// reorderJoinArgsForFlagParse lets `clawpatrol join` accept flags either
// before or after the gateway URL. Go's flag package stops parsing at the
// first positional argument, but the CLI help historically showed the URL
// first followed by optional flags.
func reorderJoinArgsForFlagParse(args []string) []string {
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		name := strings.TrimLeft(arg, "-")
		name, _, hasValue := strings.Cut(name, "=")
		flags = append(flags, arg)
		switch name {
		case "hostname", "profile", "name", "ca-dir":
			if !hasValue && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, positional...)
}

// runJoin is the entry point for a brand-new client without Tailscale.
// Walks the device-flow onboarding (admin approves on dashboard via
// existing tailnet device), installs Tailscale, joins, then continues
// straight into the post-join setup (set exit-node, fetch CA, install
// system trust) — single command, full setup.
func runJoin(args []string) {
	// `sudo clawpatrol join` lands wg.conf + api-token as root:root in
	// /root/.config/clawpatrol, then the user's `clawpatrol run` (no
	// sudo) can't read them. The CA-install step is the only piece that
	// needs elevated rights, and runAsRoot() shells out to sudo on demand.
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		fail("don't run join under sudo — invoke as your normal user; I'll sudo internally for the CA install step")
	}
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	gwName := fs.String("name", "clawpatrol", "exit-node hostname on the tailnet (only used with --whole-machine)")
	caOut := fs.String("ca-dir", defaultClawpatrolDir(), "where to store the fetched CA")
	skipTrust := fs.Bool("no-trust", false, "fetch CA but skip system trust install (do it manually)")
	wholeMachine := fs.Bool("whole-machine", false, "bring up wg-quick to route ALL host traffic through the gateway (default: persist conf only, use `clawpatrol run` for per-process routing)")
	profile := fs.String("profile", "", "profile to assign at approval time (defaults to the gateway's default profile if the approver doesn't pick one)")
	hostname := fs.String("hostname", "", "device name to register with the gateway (defaults to os.Hostname)")
	_ = fs.Parse(reorderJoinArgsForFlagParse(args))
	rest := fs.Args()
	if len(rest) != 1 || rest[0] == "" {
		fail("usage: clawpatrol join [--hostname NAME] [--profile NAME] [--whole-machine] <gateway-url>")
	}
	gatewayURL := rest[0]
	if *wholeMachine {
		if local, reason := isLocalGateway(gatewayURL); local {
			fail("refusing --whole-machine join: gateway URL points at this host (%s).\n"+
				"  Whole-machine routing on the gateway box itself creates a routing loop —\n"+
				"  the gateway daemon's own outbound traffic would re-enter its own tunnel.\n"+
				"  Drop --whole-machine and use `clawpatrol run` for per-process routing\n"+
				"  on this host, or run `clawpatrol join` from a separate client device.",
				reason)
		}
	}
	// Fetch CA BEFORE the VPN goes up. Once `wg-quick up` flips
	// the default route through the gateway, reaching the
	// gateway's public URL goes via the tunnel — which can't
	// carry traffic until the gateway has internet egress
	// configured (MASQUERADE etc). The CA is small + cheap and
	// the onboard endpoints are reachable on the public path.
	//
	// In Tailscale control mode the gateway intentionally does not
	// expose /ca.crt on its public Funnel path — the CA is only
	// reachable over the tailnet (security: no TOFU over plain
	// internet). A 404 here means we're talking to a Tailscale-mode
	// gateway; onboardViaDeviceFlow fetches the CA from the peer's
	// tailnet IP after joining.
	//
	// Trust install + shell-rc updates are deferred to
	// finishJoinSetup, which runs only after the operator's
	// dashboard approval click.
	setup, err := preJoinFetchCA(gatewayURL, *caOut)
	if err != nil && !isCaNotExposed(err) {
		fail("ca fetch: %v", err)
	}
	wgMode, err := onboardViaDeviceFlow(gatewayURL, *wholeMachine, *profile, *hostname, &setup, *skipTrust)
	if err != nil {
		fail("join: %v", err)
	}
	if wgMode {
		return
	}
	// Whole-machine Tailscale (Linux only): route all host traffic via
	// the gateway by setting it as exit-node on the system tailscaled.
	// Skipped for per-process tsnet mode and for macOS (where the NE
	// extension owns routing — never system tailscale).
	if *wholeMachine && runtime.GOOS == "linux" {
		// Use the actual registered tsnet node name as the exit-node
		// target, not the --name default. onboardViaDeviceFlow's
		// whole-machine branch persists this at tailnet-gateway.
		exitNode := *gwName
		gwHostFile := strings.TrimSpace(readFileSilent(filepath.Join(*caOut, "tailnet-gateway")))
		if gwHostFile != "" {
			exitNode = gwHostFile
		}
		if err := applyWholeMachineExitNode(exitNode); err != nil {
			fail("%v", err)
		}
	}
}

// joinSetup carries the post-join side-effect status so the caller
// renders a single coherent block instead of interleaving "✓ ca…" /
// "⚠ shell rc…" lines around the device-flow output.
type joinSetup struct {
	caInstalled   bool   // installed into system trust
	caPath        string // on-disk path to the fetched cert
	caHint        string // manual-trust hint when caInstalled == false
	caFingerprint string // SHA-256 of the fetched cert (operator-readable)
	shellRC       bool   // shell rc updated with `eval "$(clawpatrol env)"`
}

// isCaNotExposed returns true when the gateway deliberately did not expose
// /ca.crt on its public path (Tailscale control mode). The CA is then
// fetched securely over the tailnet by onboardViaDeviceFlow.
func isCaNotExposed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "status 404")
}

// preJoinFetchCA downloads the gateway's CA into caDir and computes
// its SHA-256 fingerprint, but stops short of installing it into
// the system trust store. Trust install + shell-rc updates land in
// finishJoinSetup, which runs only once the operator has approved
// the device on the dashboard.
//
// Splitting the flow this way puts the visual-fingerprint compare
// in the loop: an on-path attacker who served a substitute CA over
// plain HTTP loses because the dashboard surfaces the gateway's
// real fingerprint and the operator can refuse to approve.
func preJoinFetchCA(gateway, caDir string) (joinSetup, error) {
	var s joinSetup
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return s, fmt.Errorf("mkdir %s: %w", caDir, err)
	}
	// Persist the dashboard URL before the CA fetch so subsequent
	// `clawpatrol env` / `clawpatrol run` invocations work even when
	// the CA fetch is deferred (Tailscale mode, 404 on /ca.crt).
	_ = os.WriteFile(filepath.Join(caDir, "gateway"),
		[]byte(strings.TrimRight(gateway, "/")+"\n"), 0o644)
	s.caPath = filepath.Join(caDir, "ca.crt")
	fp, err := fetchCAHTTP(gateway, s.caPath)
	if err != nil {
		return s, fmt.Errorf("fetch CA: %w", err)
	}
	s.caFingerprint = fp
	return s, nil
}

// finishJoinSetup runs the trust-install + shell-rc steps that
// were held back from preJoinFetchCA. The caller invokes this
// only after the operator's dashboard approval has confirmed the
// CA fingerprint matches — so the CA we install can't be one
// substituted by an on-path attacker at fetch time.
//
// installShellRC fires only in --whole-machine mode. In
// per-process mode every agent picks up CA + push-down vars
// through `clawpatrol run`, so the shell-rc shim is dead weight
// — and worse, the `clawpatrol env` it eval's on every new
// terminal would dial the gateway's tailnet IP, which the
// parent shell can't reach (only the NE can).
func finishJoinSetup(s *joinSetup, skipTrust, wholeMachine bool) {
	if s.caPath == "" {
		return
	}
	if _, err := os.Stat(s.caPath); err != nil {
		// CA not fetched yet (Tailscale mode defers the fetch to the
		// tailnet path inside onboardViaDeviceFlow). Skip trust install
		// here; it lands once the CA arrives.
		if wholeMachine {
			installShellRC() //nolint:errcheck
		}
		return
	}
	if !skipTrust {
		if err := installCATrust(s.caPath); err != nil {
			s.caHint = manualTrustHint(s.caPath)
		} else {
			s.caInstalled = true
		}
	} else {
		s.caHint = manualTrustHint(s.caPath)
	}
	if wholeMachine {
		if err := installShellRC(); err == nil {
			s.shellRC = true
		}
	}
}

// fetchCAHTTP downloads the CA from gateway, writes it to dst,
// and returns the SHA-256 fingerprint of the cert it received.
// The fingerprint flows back to the CLI's stdout so the operator
// can compare it against what the dashboard shows during the
// approval step.
func fetchCAHTTP(gateway, dst string) (string, error) {
	url := strings.TrimRight(gateway, "/") + "/ca.crt"
	// InsecureSkipVerify is intentional here: we haven't yet fetched the CA
	// that signed the gateway's cert, so we can't verify it. The admin confirms
	// the fingerprint out-of-band (shown in the UI at join time) — TOFU.
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fp, err := caFingerprintFromPEM(b)
	if err != nil {
		return "", fmt.Errorf("parse CA: %w", err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return "", err
	}
	return fp, nil
}

// installShellRC appends `eval "$(clawpatrol env)"` to the user's shell
// rc file (idempotent — looks for the existing marker line). This way
// agent CLIs (claude, gh, codex) automatically pick up the placeholder
// tokens + CA bundle in every new shell, no manual sourcing needed.
func installShellRC() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	const marker = "# clawpatrol: agent env (clawpatrol env)"
	const block = "\n" + "# clawpatrol: agent env (clawpatrol env)\n" +
		"command -v clawpatrol >/dev/null 2>&1 && eval \"$(clawpatrol env)\"\n"
	for _, name := range []string{".zshrc", ".bashrc", ".profile"} {
		p := filepath.Join(home, name)
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if strings.Contains(string(b), marker) {
			return nil // already installed
		}
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(block); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	return nil
}

func fetchCA(ip, dst string) error {
	url := fmt.Sprintf("http://%s:8080/ca.crt", ip)
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func installCATrust(caPath string) error {
	fmt.Println("Installing CA certificate into system trust store (requires sudo)...")
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("sudo", "security", "add-trusted-cert",
			"-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain",
			caPath).Run()
	case "linux":
		dst := "/usr/local/share/ca-certificates/clawpatrol.crt"
		if err := exec.Command("sudo", "cp", caPath, dst).Run(); err != nil {
			return err
		}
		return exec.Command("sudo", "update-ca-certificates").Run()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func manualTrustHint(caPath string) string {
	switch runtime.GOOS {
	case "darwin":
		return fmt.Sprintf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", caPath)
	case "linux":
		return fmt.Sprintf("sudo cp %s /usr/local/share/ca-certificates/clawpatrol.crt && sudo update-ca-certificates", caPath)
	}
	return "manually add " + caPath + " to your system trust store"
}

// pinDNSAtGatewayIfNeeded writes /etc/resolv.conf → nameserver gwIP on
// Linux hosts that don't run systemd-resolved. tsnet has no UDP
// fallback, so client DNS to a public nameserver via the exit-node is
// silently dropped at the gateway's netstack. Pointing the client at
// the gateway routes queries through serveTsnetDNSUDP. Hosts running
// systemd-resolved are already fine — their queries source-bind to
// the physical link DNS and bypass the exit-node.
func pinDNSAtGatewayIfNeeded(gwIP string) {
	if runtime.GOOS != "linux" || gwIP == "" {
		return
	}
	if exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil {
		return
	}
	const path = "/etc/resolv.conf"
	cur, _ := os.ReadFile(path)
	desired := fmt.Sprintf("# clawpatrol: routed via Tailscale exit-node\nnameserver %s\n", gwIP)
	if strings.Contains(string(cur), gwIP) && strings.Contains(string(cur), "clawpatrol:") {
		return
	}
	if _, err := os.Stat(path + ".clawpatrol.bak"); errors.Is(err, os.ErrNotExist) && len(cur) > 0 {
		_ = writeSudo(path+".clawpatrol.bak", cur)
	}
	if err := writeSudo(path, []byte(desired)); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ resolv.conf: %v\n", err)
		return
	}
	fmt.Printf("DNS pinned to gateway (%s)\n", gwIP)
}

func writeSudo(path string, content []byte) error {
	cmd := exec.Command("sudo", "tee", path)
	cmd.Stdin = bytes.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func defaultClawpatrolDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".clawpatrol")
}

// daemonStateDir returns the per-user **persistent** directory for
// daemon-only state (auth-key, future daemon-private files). XDG
// spec: $XDG_STATE_HOME/clawpatrol, fall back to
// ~/.local/state/clawpatrol when unset. Separate from
// defaultClawpatrolDir so that the agent-visible ~/.clawpatrol/
// directory only holds files the agent legitimately needs (ca.crt,
// mode marker, etc.).
func daemonStateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "clawpatrol")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "clawpatrol")
}

// readFileSilent reads a file and returns its contents as a string,
// or empty on any error.
func readFileSilent(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "clawpatrol: "+format+"\n", a...)
	os.Exit(2)
}

// startSpinner paints a braille spinner + label on the current line and
// returns a stop function that clears the line. Tick is 80ms — fast
// enough to feel alive while the device-flow poll loop sits on its
// 3-second interval. Writes only land on stderr-attached TTYs; if stdout
// isn't a terminal (CI, piped logs) the spinner suppresses itself so it
// doesn't scribble control codes into log files.
func startSpinner(label string) func() {
	if !isTerminal(os.Stdout) {
		return func() {}
	}
	frames := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		i := 0
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				fmt.Printf("\r\033[K")
				return
			case <-t.C:
				fmt.Printf("\r%c %s", frames[i%len(frames)], label)
				i++
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// printTreeItems prints a list as ├-prefixed sub-items with the final
// entry marked └ (bottom-corner). Same box-drawing family so the glyphs
// align visually instead of mixing the heavier ⎿ corner.
func printTreeItems(items []string) {
	for i, line := range items {
		prefix := "├ "
		if i == len(items)-1 {
			prefix = "└ "
		}
		fmt.Println(prefix + line)
	}
}

// setupSummaryItems lowers a joinSetup into the human-facing one-liners
// the join / login output blocks render. CA-trust failures and skipped
// shell-rc updates surface as their own items so the operator sees what
// they need to do manually; success cases stay quiet to keep the block
// short.
func setupSummaryItems(s joinSetup) []string {
	var out []string
	switch {
	case s.caInstalled:
		out = append(out, "CA installed in system trust")
	case s.caHint != "":
		out = append(out, "CA at "+s.caPath+" — trust manually: "+s.caHint)
	}
	if s.shellRC {
		out = append(out, `Shell rc: eval "$(clawpatrol env)"`)
	}
	return out
}

// onboardViaDeviceFlow: brand-new client (no tailscale yet) calls the
// gateway dashboard, gets a user_code, prompts the user to approve on
// an existing trusted device, polls for the minted Tailscale auth key,
// installs Tailscale (if missing), and runs `tailscale up --authkey`.
// wgAddressFromConf parses the `Address = X.Y.Z.W/32` line out of a
// wg-quick config so the CLI can send its peer IP to the gateway
// before bringing the tunnel up. Returns "" when the conf has no
// Address attribute or the value is unparseable.
func wgAddressFromConf(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Address") {
			continue
		}
		_, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, "/"); i > 0 {
			v = v[:i]
		}
		return v
	}
	return ""
}

// onboardViaDeviceFlow drives the device-flow handshake against the
// gateway and ends in a working VPN connection. Returns wgMode=true
// when the gateway picked the wireguard control plane (caller skips
// tailscale-specific post-setup). profile, when non-empty, is sent
// to the gateway as the suggested profile for this device — the
// approver can still override it from the dashboard. hostname, when
// non-empty, overrides os.Hostname() for the device name registered
// with the gateway.
//
// setup carries the CA fetched by preJoinFetchCA. Once approval
// lands, finishJoinSetup installs that CA into the system trust
// store — the approval click is the operator's confirmation that
// the fingerprint the dashboard showed matched what the CLI
// printed, so the CA we install can't be one a MITM substituted
// during the unauthenticated /ca.crt fetch.
func onboardViaDeviceFlow(gateway string, wholeMachine bool, profile, hostname string, setup *joinSetup, skipTrust bool) (bool, error) {
	gateway = strings.TrimRight(gateway, "/")
	// CA is unverified until the admin confirms the fingerprint at approval time
	// (TOFU). Use InsecureSkipVerify throughout the join handshake.
	cli := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	hn := hostname
	if hn == "" {
		hn, _ = os.Hostname()
	}

	// 1. start — pass our hostname so the dashboard shows a real
	// device name in WG mode (no whois fallback there).
	q := neturl.Values{}
	if hn != "" {
		q.Set("hostname", hn)
	}
	if profile != "" {
		q.Set("profile", profile)
	}
	if wholeMachine {
		q.Set("whole_machine", "1")
	}
	startURL := gateway + "/api/onboard/start"
	if encoded := q.Encode(); encoded != "" {
		startURL += "?" + encoded
	}
	resp, err := cli.Post(startURL, "application/json", nil)
	if err != nil {
		return false, fmt.Errorf("start: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("start: %d %s", resp.StatusCode, string(b))
	}
	var start struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		VerifyURL  string `json:"verify_url"`
		Interval   int    `json:"interval"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&start); err != nil {
		return false, fmt.Errorf("start decode: %w", err)
	}

	fmt.Println()
	fmt.Println("Verify code in browser:")
	fmt.Println()
	fmt.Printf("    %s\n", start.UserCode)
	fmt.Println()
	fmt.Println(start.VerifyURL)
	// One-line CA fingerprint after the verify URL. The
	// dashboard's approval page shows the same value next to
	// the user_code — operator visually confirms they match
	// before clicking approve, blocking an on-path swap of the
	// CA the CLI just fetched over plain HTTP.
	if setup != nil && setup.caFingerprint != "" {
		fmt.Println()
		fmt.Printf("CA fingerprint: %s\n", setup.caFingerprint)
	}
	fmt.Println()
	// Tailnet-only verify URLs (100.64.0.0/10 IP or *.ts.net host) are
	// unreachable from the machine running `clawpatrol join` until
	// approval lands — that's the whole point of needing approval. Print
	// a QR code so the operator can scan from a phone or another
	// already-tailnet-connected device. Skip tryOpen on that path: a
	// local browser can't reach the URL anyway, and the spawned
	// xdg-open / open process just produces a meaningless tab.
	if isTailnetOnlyURL(start.VerifyURL) {
		printVerifyQR(start.VerifyURL)
	} else {
		tryOpen(start.VerifyURL)
	}

	// 2. poll
	interval := time.Duration(start.Interval) * time.Second
	if interval == 0 {
		interval = 3 * time.Second
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)

	// In whole-machine mode the clawpatrol WireGuard tunnel already routes
	// all traffic — including these poll requests. When the admin approves,
	// MintKey evicts our old peer from the gateway device, killing the
	// tunnel mid-poll and hanging the spinner indefinitely. Bring it down
	// before polling so requests go over the regular internet.
	if wholeMachine {
		_ = runAsRoot("wg-quick", "down", "clawpatrol").Run()
	}

	stopSpin := startSpinner("Waiting for approval")
	authKey, loginServer, apiToken := "", "", ""
	var tailnetGWHost, tailnetControlURL, gatewayIP, caPEM string
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		pr, err := cli.Post(gateway+"/api/onboard/poll?device_code="+start.DeviceCode, "application/json", nil)
		if err != nil {
			continue
		}
		var pv map[string]string
		_ = json.NewDecoder(pr.Body).Decode(&pv)
		_ = pr.Body.Close()
		if k, ok := pv["auth_key"]; ok && k != "" {
			authKey = k
			loginServer = pv["login_server"]
			apiToken = pv["api_token"]
			tailnetGWHost = pv["gateway_host"]
			tailnetControlURL = pv["control_url"]
			gatewayIP = pv["gateway_ip"]
			caPEM = pv["ca_pem"]
			break
		}
		if e := pv["error"]; e != "" && e != "authorization_pending" && e != "slow_down" {
			stopSpin()
			return false, fmt.Errorf("poll: %s (%s)", e, pv["detail"])
		}
	}
	stopSpin()
	if authKey == "" {
		return false, fmt.Errorf("timed out waiting for approval")
	}
	fmt.Println("Approved.")
	// Approval click ⇒ operator visually confirmed the CA
	// fingerprint on the dashboard matched what the CLI
	// printed. Only now is it safe to push the fetched CA
	// into the system trust store. Doing this earlier would
	// have meant trusting a CA the operator hadn't vouched
	// for, which is exactly the on-path attack we're closing.
	finishJoinSetup(setup, skipTrust, wholeMachine)
	// Persist the per-peer bearer the gateway minted alongside the
	// wg conf. Lives next to ca.crt — same dir the env-pushdown
	// fetcher reads. Best-effort; missing file means env-pushdown
	// will refuse to authenticate and the operator gets a clear
	// stderr warning instead of a silent fall-through.
	if apiToken != "" {
		_ = os.WriteFile(filepath.Join(filepath.Dir(setup.caPath), "api-token"),
			[]byte(apiToken+"\n"), 0o600)
	}

	// 3a. wireguard branch — auth_key is the full client config.
	// Skip tailscale entirely (no daemon, no `tailscale up`). The
	// gateway runs an L3 forwarder that catches SYNs to ANY dst IP
	// once we route 0.0.0.0/0 into the tunnel, so we don't pin
	// /etc/hosts and don't need a /api/onboard/claim round-trip —
	// the server registered our peer IP against the approver at
	// mint time.
	if strings.HasPrefix(loginServer, "wireguard://") {
		iface := strings.TrimPrefix(loginServer, "wireguard://")
		if iface == "" {
			iface = "clawpatrol"
		}
		// Send our hostname BEFORE wg-quick brings the tunnel up — once
		// 0.0.0.0/0 routes through the tunnel the public gateway URL
		// becomes unreachable. Server's /api/onboard/approve already
		// registered the (peerIP → owner) mapping at mint time, but
		// the hostname only landed if the CLI sent it at /start. This
		// claim call is idempotent on owner and updates the hostname
		// row in the devices table.
		if hn != "" {
			wgIP := wgAddressFromConf(authKey)
			claimURL := fmt.Sprintf("%s/api/onboard/claim?device_code=%s&hostname=%s",
				gateway, start.DeviceCode, neturl.QueryEscape(hn))
			if wgIP != "" {
				claimURL += "&ip=" + neturl.QueryEscape(wgIP)
			}
			if cr, err := cli.Post(claimURL, "application/json", nil); err == nil {
				_ = cr.Body.Close()
			}
		}
		// Always persist a user-readable copy at ~/.config/clawpatrol/
		// wg.conf so the per-host `clawpatrol` daemon (Linux) and the
		// macOS NE extension can spin up a userspace WG tunnel without
		// reading root-owned /etc/wireguard/<iface>.conf.
		var persistErr error
		if err := writeUserWGConf(authKey); err != nil {
			persistErr = err
		}
		// Mode marker — read by the daemon at startup to pick the
		// transport. Default (no marker) also defaults to wireguard,
		// but writing it explicitly avoids surprises if a host has
		// stale state from a previous tailscale-mode join.
		_ = os.WriteFile(filepath.Join(filepath.Dir(setup.caPath), "mode"),
			[]byte("wireguard\n"), 0o600)
		// macOS: kick off the NE bootstrap right after the wg.conf is
		// in place. Surfaces the one-time sysext approval prompt now
		// (better than waiting until first `clawpatrol run`).
		var macErr error
		if runtime.GOOS == "darwin" {
			macErr = macHelperInstall(wholeMachine)
		}
		items := []string{}
		if wgIP := wgAddressFromConf(authKey); wgIP != "" {
			items = append(items, "Joined as "+wgIP)
		} else {
			items = append(items, "Joined")
		}
		items = append(items, setupSummaryItems(*setup)...)
		printTreeItems(items)
		fmt.Println()
		if !wholeMachine {
			fmt.Println("Installed! Try: clawpatrol run claude")
		} else if runtime.GOOS == "darwin" {
			fmt.Println("Installed! All host traffic routes via the system extension.")
		} else {
			if err := wgQuickUp(iface, authKey); err != nil {
				return true, fmt.Errorf("wg-quick up: %w", err)
			}
			fmt.Printf("Installed! All host traffic routes via the gateway (%s).\n", iface)
		}
		if persistErr != nil {
			fmt.Fprintf(os.Stderr, "⚠ persist user wg conf: %v\n", persistErr)
		}
		if macErr != nil {
			fmt.Fprintf(os.Stderr, "⚠ macos NE bootstrap: %v\n", macErr)
		}
		return true, nil
	}

	// 3b. tailscale branch — ensure binary + daemon.
	//
	// Per-process tsnet mode: the in-process tsnet node joins the
	// tailnet at `clawpatrol run` time using the auth_key persisted
	// below. No system Tailscale touched.
	//
	// macOS NEVER uses system Tailscale — the NETransparentProxyProvider
	// (Clawpatrol.app system extension) handles all routing. --whole-
	// machine on darwin is honored at NE-config time, not here.
	//
	// On Linux, --whole-machine falls through to the system-Tailscale
	// branch below (install tailscale + `tailscale up` + exit-node) for
	// hosts that want all traffic routed through the gateway.
	if !wholeMachine || runtime.GOOS == "darwin" {
		clawDir := filepath.Dir(setup.caPath)
		// Write CA delivered in the poll response (gateway's /ca.crt is
		// intentionally not public in tsnet mode). Then install trust.
		if caPEM != "" {
			if werr := os.WriteFile(setup.caPath, []byte(caPEM), 0o644); werr == nil {
				if fp, ferr := caFingerprintFromPEM([]byte(caPEM)); ferr == nil {
					setup.caFingerprint = fp
				}
				if !skipTrust {
					if ierr := installCATrust(setup.caPath); ierr == nil {
						setup.caInstalled = true
					} else {
						setup.caHint = manualTrustHint(setup.caPath)
					}
				} else {
					setup.caHint = manualTrustHint(setup.caPath)
				}
			}
		}
		_ = os.WriteFile(filepath.Join(clawDir, "mode"), []byte("tailscale\n"), 0o600)
		// Persist the join-time --hostname so the per-host daemon
		// registers under the operator-chosen name instead of
		// os.Hostname() (which on most VMs is the system login, not
		// the intended bot identity).
		if hn != "" {
			_ = os.WriteFile(filepath.Join(clawDir, "hostname"), []byte(hn+"\n"), 0o600)
		}
		if tailnetGWHost != "" {
			_ = os.WriteFile(filepath.Join(clawDir, "tailnet-gateway"), []byte(tailnetGWHost+"\n"), 0o600)
		}
		_ = os.WriteFile(filepath.Join(clawDir, "control-url"), []byte(tailnetControlURL+"\n"), 0o600)
		if gatewayIP != "" {
			tailnetURL := fmt.Sprintf("http://%s:8080", gatewayIP)
			_ = os.WriteFile(filepath.Join(clawDir, "tailnet-url"), []byte(tailnetURL+"\n"), 0o600)
			// Used by `clawpatrol run` to set the gateway as its tsnet
			// exit node so the gateway sees the original dst via
			// RegisterFallbackTCPHandler (no PROXY-header smuggling).
			_ = os.WriteFile(filepath.Join(clawDir, "tailnet-gateway-ip"), []byte(gatewayIP+"\n"), 0o600)
		}
		// tsnet auth-key persistence — platform split.
		//
		// macOS: hand the key directly to the NE extension via
		// NETransparentProxyManager's providerConfiguration (system-
		// owned VPN preferences storage). The user-side CLI never
		// holds the bearer on disk.
		//
		// Linux: write to the daemon's persistent state directory
		// (separate from ~/.clawpatrol, which holds agent-visible
		// files like ca.crt). The clawpatrol daemon is the sole
		// reader.
		if runtime.GOOS == "darwin" {
			c := exec.Command(macHelperPath, "start-tsnet",
				authKey, tailnetControlURL, tailnetGWHost, gatewayIP, apiToken, hn)
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			if err := c.Run(); err != nil {
				return false, fmt.Errorf("macHelper start-tsnet: %w", err)
			}
		} else {
			stateDir := daemonStateDir()
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				return false, fmt.Errorf("daemon state dir: %w", err)
			}
			_ = os.WriteFile(filepath.Join(stateDir, "auth-key"), []byte(authKey+"\n"), 0o600)
		}
		items := []string{"Joined (tsnet mode — persistent daemon node joins tailnet on first `clawpatrol run`)"}
		items = append(items, setupSummaryItems(*setup)...)
		printTreeItems(items)
		fmt.Println()
		fmt.Println("Installed! Try: clawpatrol run claude")
		return false, nil
	}

	if _, err := tailscaleBin(); err != nil {
		fmt.Println("└ Installing tailscale (will require sudo)")
		if err := installTailscale(); err != nil {
			return false, fmt.Errorf("install tailscale: %w", err)
		}
	}
	tscli, err := tailscaleBin()
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "linux" {
		// `tailscale up` needs tailscaled. The install.sh script
		// usually enables it, but some VMs / docker images leave it
		// disabled. Start unconditionally — systemctl is idempotent.
		_ = exec.Command("sudo", "systemctl", "enable", "--now", "tailscaled").Run()
	}

	// 4b. tailscale up — set --operator on linux so future
	// `tailscale set/serve/funnel` calls don't need sudo.
	// On macOS the App Store Tailscale daemon handles auth via the
	// menu-bar app; running `sudo tailscale up` crashes with a
	// BundleIdentifiers fatal error. Run without sudo on non-Linux.
	upArgs := []string{"up", "--reset", "--authkey=" + authKey, "--accept-routes", "--accept-dns=false"}
	if runtime.GOOS == "linux" {
		if u := os.Getenv("USER"); u != "" {
			upArgs = append(upArgs, "--operator="+u)
		}
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		cmd = exec.Command("sudo", append([]string{tscli}, upArgs...)...)
	} else {
		cmd = exec.Command(tscli, upArgs...)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("tailscale up: %w", err)
	}

	// 5. claim — tell gateway "this tailnet IP belongs to <approver>".
	myIP, _ := exec.Command(tscli, "ip", "-4").Output()
	tailIP := strings.TrimSpace(strings.SplitN(string(myIP), "\n", 2)[0])
	if tailIP == "" {
		fmt.Fprintln(os.Stderr, "⚠ couldn't read tailnet IP — onboard claim skipped")
		return false, nil
	}
	claimURL := fmt.Sprintf("%s/api/onboard/claim?device_code=%s&ip=%s",
		gateway, start.DeviceCode, tailIP)
	if hn != "" {
		claimURL += "&hostname=" + neturl.QueryEscape(hn)
	}
	cr, err := cli.Post(claimURL, "application/json", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ onboard claim failed: %v\n", err)
		return false, nil
	}
	defer func() { _ = cr.Body.Close() }()
	if cr.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(cr.Body, 400))
		fmt.Fprintf(os.Stderr, "⚠ onboard claim %d: %s\n", cr.StatusCode, string(body))
		return false, nil
	}
	var claimResp map[string]string
	if err := json.NewDecoder(cr.Body).Decode(&claimResp); err == nil {
		if tok := claimResp["api_token"]; tok != "" {
			_ = os.WriteFile(filepath.Join(filepath.Dir(setup.caPath), "api-token"),
				[]byte(tok+"\n"), 0o600)
		}
	}

	// Write mode marker files so `clawpatrol run` can detect Tailscale mode.
	clawDir := filepath.Dir(setup.caPath)
	_ = os.WriteFile(filepath.Join(clawDir, "mode"), []byte("tailscale\n"), 0o600)
	if hn != "" {
		_ = os.WriteFile(filepath.Join(clawDir, "hostname"), []byte(hn+"\n"), 0o600)
	}
	if tailnetGWHost != "" {
		_ = os.WriteFile(filepath.Join(clawDir, "tailnet-gateway"), []byte(tailnetGWHost+"\n"), 0o600)
	}
	if tailnetControlURL != "" {
		_ = os.WriteFile(filepath.Join(clawDir, "control-url"), []byte(tailnetControlURL+"\n"), 0o600)
	}

	// Fetch CA from the gateway's tailnet IP now that we're on the tailnet.
	// The public /ca.crt path returns 404 for Tailscale-mode gateways; the
	// tailnet fetch is the secure path. Skip if CA was already fetched (WG
	// gateways expose it publicly).
	// Look up the gateway peer on the tailnet to:
	//   a) save the tailnet-direct URL (bypasses Funnel for peer API calls)
	//   b) fetch CA if not yet on disk (Tailscale-mode gateways 404 /ca.crt publicly)
	if tailnetGWHost != "" {
		if st2, serr := tailscaleStatus(tscli); serr == nil {
			// tailnetGWHost may be an FQDN like "clawpatrol-1.tail9a48e.ts.net";
			// HostName in `tailscale status` is the short name "clawpatrol-1".
			shortName := tailnetGWHost
			if i := strings.IndexByte(shortName, '.'); i > 0 {
				shortName = shortName[:i]
			}
			if peer := findPeerByName(st2, shortName); peer != nil && len(peer.TailscaleIPs) > 0 {
				// Persist tailnet-direct URL so clawpatrol run uses it for peer
				// API calls instead of the public join URL, which may be
				// Funnel-proxied and not expose peer-API endpoints. Port 8080
				// is the gateway's InfoListen (plain HTTP on the tailnet).
				tailnetURL := fmt.Sprintf("http://%s:8080", peer.TailscaleIPs[0])
				_ = os.WriteFile(filepath.Join(clawDir, "tailnet-url"), []byte(tailnetURL+"\n"), 0o600)
				_ = os.WriteFile(filepath.Join(clawDir, "tailnet-gateway-ip"),
					[]byte(peer.TailscaleIPs[0]+"\n"), 0o600)
				if _, serr := os.Stat(setup.caPath); serr != nil {
					if ferr := fetchCA(peer.TailscaleIPs[0], setup.caPath); ferr == nil {
						if !skipTrust {
							if ierr := installCATrust(setup.caPath); ierr != nil {
								setup.caHint = manualTrustHint(setup.caPath)
							} else {
								setup.caInstalled = true
							}
						} else {
							setup.caHint = manualTrustHint(setup.caPath)
						}
					}
				}
			}
		}
	}
	if wholeMachine {
		if err := installShellRC(); err == nil {
			setup.shellRC = true
		}
	}

	items := []string{"Joined tailnet as " + tailIP}
	items = append(items, setupSummaryItems(*setup)...)
	printTreeItems(items)
	fmt.Println()
	fmt.Println("Installed! Try: clawpatrol run -- claude")

	return false, nil
}

func tryOpen(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "linux":
		cmd = exec.Command("xdg-open", u)
	default:
		return
	}
	_ = cmd.Start()
}

// runAsRoot prepends "sudo" only when the caller isn't already root
// AND sudo is on PATH. Containers / cloud-init bootstraps frequently
// run as root with no sudo binary; barfing in that case is rude.
func runAsRoot(cmd string, args ...string) *exec.Cmd {
	if os.Geteuid() == 0 {
		return exec.Command(cmd, args...)
	}
	if _, err := exec.LookPath("sudo"); err == nil {
		return exec.Command("sudo", append([]string{cmd}, args...)...)
	}
	// last resort — try without sudo, let the OS reject if it must.
	return exec.Command(cmd, args...)
}
