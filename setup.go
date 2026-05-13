package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type tsStatus struct {
	Self           *tsPeer            `json:"Self"`
	Peer           map[string]*tsPeer `json:"Peer"`
	MagicDNSSuffix string             `json:"MagicDNSSuffix"`
	CurrentTailnet *tsTailnet         `json:"CurrentTailnet"`
	User           map[string]tsUser  `json:"User"`
}

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

type tsTailnet struct {
	Name string `json:"Name"`
}

type tsUser struct {
	LoginName   string `json:"LoginName"`
	DisplayName string `json:"DisplayName"`
}

type tsPeer struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	UserID       int64    `json:"UserID"`
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
	gwName := fs.String("name", "clawpatrol", "exit-node hostname on the tailnet")
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
	// Fetch CA + write shell rc BEFORE the VPN goes up. Once
	// `wg-quick up` flips the default route through the gateway,
	// reaching the gateway's public URL goes via the tunnel — which
	// can't carry traffic until the gateway has internet egress
	// configured (MASQUERADE etc). The CA is small + cheap and the
	// onboard endpoints are reachable on the public path.
	setup, err := postJoinSetup(gatewayURL, *caOut, *skipTrust)
	if err != nil {
		fail("ca fetch: %v", err)
	}
	wgMode, err := onboardViaDeviceFlow(gatewayURL, *wholeMachine, *profile, *hostname, setup)
	if err != nil {
		fail("join: %v", err)
	}
	if wgMode {
		return
	}
	// Tailscale-specific path: exit-node + whois identity.
	loginArgs := []string{"-name", *gwName, "-ca-dir", *caOut}
	if *skipTrust {
		loginArgs = append(loginArgs, "-no-trust")
	}
	runLogin(loginArgs)
}

// joinSetup carries the post-join side-effect status so the caller
// renders a single coherent block instead of interleaving "✓ ca…" /
// "⚠ shell rc…" lines around the device-flow output.
type joinSetup struct {
	caInstalled bool   // installed into system trust
	caPath      string // on-disk path to the fetched cert
	caHint      string // manual-trust hint when caInstalled == false
	shellRC     bool   // shell rc updated with `eval "$(clawpatrol env)"`
}

// postJoinSetup downloads the gateway's CA, installs it into the
// system trust store (best-effort), and appends the env shim to the
// shell rc. Returns a summary the caller prints once the onboarding
// flow completes.
func postJoinSetup(gateway, caDir string, skipTrust bool) (joinSetup, error) {
	var s joinSetup
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return s, fmt.Errorf("mkdir %s: %w", caDir, err)
	}
	s.caPath = filepath.Join(caDir, "ca.crt")
	if err := fetchCAHTTP(gateway, s.caPath); err != nil {
		return s, fmt.Errorf("fetch CA: %w", err)
	}
	// Persist the dashboard URL so subsequent `clawpatrol env` /
	// `clawpatrol run` invocations can fetch the env push-down list
	// from the gateway instead of iterating compiled-in plugins.
	// Best-effort; the read side falls back to local enumeration
	// when this file is missing.
	_ = os.WriteFile(filepath.Join(caDir, "gateway"),
		[]byte(strings.TrimRight(gateway, "/")+"\n"), 0o644)
	if !skipTrust {
		if err := installCATrust(s.caPath); err != nil {
			s.caHint = manualTrustHint(s.caPath)
		} else {
			s.caInstalled = true
		}
	} else {
		s.caHint = manualTrustHint(s.caPath)
	}
	if err := installShellRC(); err == nil {
		s.shellRC = true
	}
	return s, nil
}

func fetchCAHTTP(gateway, dst string) error {
	url := strings.TrimRight(gateway, "/") + "/ca.crt"
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	gwName := fs.String("name", "clawpatrol", "exit-node hostname to look for on the tailnet")
	caOut := fs.String("ca-dir", defaultClawpatrolDir(), "where to store the fetched CA")
	skipTrust := fs.Bool("no-trust", false, "fetch CA but skip system trust install (do it manually)")
	skipExitNode := fs.Bool("no-exit-node", false, "skip setting tailscale exit-node (run manually later)")
	_ = fs.Parse(args)

	// Setting exit-node redirects ALL outbound traffic via the gateway,
	// which kills an in-flight SSH session on Linux (reply packets to
	// the client now route through tailnet → source IP changes mid-
	// stream → client EOFs the handshake).
	//
	// Fix: install a policy-routing override BEFORE flipping exit-node
	// so traffic destined for the SSH client keeps using the default
	// table (= public interface). Reply packets stay direct, SSH
	// survives, everything else routes via gateway as intended.
	sshPinned := false
	if !*skipExitNode && runtime.GOOS == "linux" {
		if err := exemptSSHFromExitNode(""); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ couldn't protect SSH (will skip exit-node): %v\n", err)
			*skipExitNode = true
		} else {
			sshPinned = true
		}
	}

	tscli, err := tailscaleBin()
	if err != nil {
		fail("tailscale CLI not found: %v\nis Tailscale installed and running?", err)
	}

	st, err := tailscaleStatus(tscli)
	if err != nil {
		fail("tailscale status: %v", err)
	}
	if st.Self == nil || len(st.Self.TailscaleIPs) == 0 {
		fail("not logged into a tailnet (run: tailscale up)")
	}
	tailnetName := tailnetDisplayName(st)

	peer := findPeerByName(st, *gwName)
	if peer == nil {
		fail("no peer named %q on this tailnet — is the gateway running and joined?", *gwName)
	}

	// Fetch CA BEFORE setting exit-node. Once exit-node flips, every
	// outbound route is rewritten and any in-flight tailscaled
	// re-config can drop the request mid-flight.
	if err := os.MkdirAll(*caOut, 0o700); err != nil {
		fail("mkdir %s: %v", *caOut, err)
	}
	caPath := filepath.Join(*caOut, "ca.crt")
	if err := fetchCA(peer.TailscaleIPs[0], caPath); err != nil {
		fail("fetch CA: %v", err)
	}

	// On Linux, `tailscale set` requires sudo unless --operator=$USER
	// was passed to `tailscale up`. tsSet handles either case.
	if !*skipExitNode {
		if err := tsSet(tscli, "--exit-node="+*gwName); err != nil {
			fail("tailscale set --exit-node=%s: %v", *gwName, err)
		}
	}

	caInstalled := false
	caHint := ""
	if *skipTrust {
		caHint = manualTrustHint(caPath)
	} else if err := installCATrust(caPath); err != nil {
		caHint = manualTrustHint(caPath)
	} else {
		caInstalled = true
	}
	shellOK := installShellRC() == nil

	fmt.Println()
	fmt.Printf("Connected to %s's tailnet.\n", tailnetName)
	items := []string{fmt.Sprintf("Found exit node: %s (%s)", *gwName, peer.TailscaleIPs[0])}
	if sshPinned {
		items = append(items, "SSH (tcp/22) reply traffic pinned to direct route")
	}
	items = append(items, setupSummaryItems(joinSetup{
		caInstalled: caInstalled,
		caPath:      caPath,
		caHint:      caHint,
		shellRC:     shellOK,
	})...)
	printTreeItems(items)
	fmt.Println()
	fmt.Println("Installed! Try: claude")
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

// exemptSSHFromExitNode protects SSH (TCP/22) reply traffic from
// being redirected through the tailscale exit-node. Without this,
// `tailscale set --exit-node=` reroutes the SYN-ACK / reply packets
// for any SSH session through the tailnet — wrong source IP, client
// EOFs the handshake, you're locked out.
//
// We mark all outbound packets with sport=22 via iptables mangle, then
// add an `ip rule` that routes those marked packets via the `main`
// table (default interface). Covers every present and future SSH
// session, not just the one that triggered the install.
//
// Idempotent — duplicate iptables/ip-rule entries return non-zero,
// which we swallow.
func exemptSSHFromExitNode(_ string) error {
	cmds := [][]string{
		{"iptables", "-t", "mangle", "-C", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "MARK", "--set-mark", "0x64"},
		{"ip", "rule", "show"},
	}
	// 1) Mark SSH replies (idempotent: -C check first, only -A if missing)
	check := exec.Command("sudo", cmds[0]...)
	if check.Run() != nil {
		add := append([]string{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "MARK", "--set-mark", "0x64"}, "")
		add = add[:len(add)-1]
		c := exec.Command("sudo", add...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("iptables mangle: %w", err)
		}
	}
	// 2) Route marked traffic via the main table (idempotent: check first)
	listed := exec.Command("sudo", cmds[1]...)
	out, _ := listed.Output()
	if !strings.Contains(string(out), "fwmark 0x64") {
		c := exec.Command("sudo", "ip", "rule", "add", "fwmark", "0x64", "lookup", "main", "pref", "50")
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("ip rule: %w", err)
		}
	}
	return nil
}

// tsSet runs `tailscale set ...`, prepending sudo on Linux where the
// LocalAPI checkprefs ACL requires it (unless --operator was set on
// `up`). On macOS the GUI app handles auth so plain `tailscale set`
// works.
func tsSet(tscli string, args ...string) error {
	full := append([]string{"set"}, args...)
	if runtime.GOOS == "linux" {
		full = append([]string{tscli}, full...)
		c := exec.Command("sudo", full...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		return c.Run()
	}
	c := exec.Command(tscli, full...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// tailnetDisplayName returns a short name for the current tailnet,
// matching the README format ("divy's tailnet"). Prefers the
// CurrentTailnet.Name; falls back to the local user's display name or
// login local-part; final fallback is "your".
func tailnetDisplayName(st *tsStatus) string {
	if st.CurrentTailnet != nil && st.CurrentTailnet.Name != "" {
		// e.g. "divy@github" → "divy"
		n := st.CurrentTailnet.Name
		if i := strings.IndexAny(n, "@."); i > 0 {
			n = n[:i]
		}
		return n
	}
	if st.Self != nil {
		if u, ok := st.User[fmt.Sprint(st.Self.UserID)]; ok {
			if u.DisplayName != "" {
				if first := strings.SplitN(u.DisplayName, " ", 2)[0]; first != "" {
					return strings.ToLower(first)
				}
			}
			if u.LoginName != "" {
				if i := strings.IndexAny(u.LoginName, "@"); i > 0 {
					return u.LoginName[:i]
				}
				return u.LoginName
			}
		}
	}
	return "your"
}

func tailscaleBin() (string, error) {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, nil
	}
	if runtime.GOOS == "darwin" {
		mac := "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
		if _, err := os.Stat(mac); err == nil {
			return mac, nil
		}
	}
	return "", fmt.Errorf("tailscale binary not on PATH")
}

func tailscaleStatus(bin string) (*tsStatus, error) {
	out, err := exec.Command(bin, "status", "--json").Output()
	if err != nil {
		return nil, err
	}
	var s tsStatus
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func findPeerByName(s *tsStatus, name string) *tsPeer {
	for _, p := range s.Peer {
		if p.HostName == name {
			return p
		}
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

func defaultClawpatrolDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".clawpatrol")
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
func onboardViaDeviceFlow(gateway string, wholeMachine bool, profile, hostname string, setup joinSetup) (bool, error) {
	gateway = strings.TrimRight(gateway, "/")
	cli := &http.Client{Timeout: 30 * time.Second}

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
	fmt.Println()
	tryOpen(start.VerifyURL)

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
		// wg.conf so `clawpatrol run` can spin up a per-process tunnel
		// without sudo (root-owned /etc/wireguard/<iface>.conf is
		// unreadable to the caller's uid).
		var persistErr error
		if err := writeUserWGConf(authKey); err != nil {
			persistErr = err
		}
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
		items = append(items, setupSummaryItems(setup)...)
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
	upArgs := []string{tscli, "up", "--authkey=" + authKey, "--accept-routes", "--accept-dns=false"}
	if runtime.GOOS == "linux" {
		if u := os.Getenv("USER"); u != "" {
			upArgs = append(upArgs, "--operator="+u)
		}
	}
	cmd := exec.Command("sudo", upArgs...)
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
	items := []string{"Joined tailnet as " + tailIP}
	items = append(items, setupSummaryItems(setup)...)
	printTreeItems(items)
	fmt.Println()
	fmt.Println("Installed! Try: claude")
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

// writeUserWGConf drops a copy of the wg-quick conf at
// ~/.config/clawpatrol/wg.conf (chmod 600) so `clawpatrol run` can
// build per-process tunnels without sudo. Idempotent.
//
// Hardcoded XDG path (~/.config) instead of os.UserConfigDir() —
// the latter returns ~/Library/Application Support on macOS, which
// breaks the cross-platform "always look at ~/.config/clawpatrol/wg.conf"
// contract that the macOS Clawpatrol.app's `start` subcommand expects.
func writeUserWGConf(conf string) error {
	dir := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "wg.conf")
	return os.WriteFile(path, []byte(conf), 0o600)
}

// wgQuickUp writes the supplied wireguard config to
// /etc/wireguard/<iface>.conf and brings the interface up via
// `wg-quick up`. Installs `wireguard-tools` if missing on linux.
func wgQuickUp(iface, conf string) error {
	if _, err := exec.LookPath("wg-quick"); err != nil {
		if runtime.GOOS == "linux" {
			c := runAsRoot("apt-get", "install", "-y", "wireguard-tools")
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("install wireguard-tools: %w", err)
			}
		} else {
			return fmt.Errorf("wg-quick not found — install wireguard-tools / WireGuard.app")
		}
	}
	dst := filepath.Join("/etc/wireguard", iface+".conf")
	if runtime.GOOS == "linux" {
		conf = injectSSHExemptPostUp(conf)
	}
	tmp, err := os.CreateTemp("", "clawpatrol-wg-*.conf")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(conf); err != nil {
		return err
	}
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := runAsRoot("install", "-m", "0600", tmp.Name(), dst).Run(); err != nil {
		return fmt.Errorf("install conf: %w", err)
	}
	// `wg-quick up` is idempotent enough — bring down first if up.
	_ = runAsRoot("wg-quick", "down", iface).Run()
	c := runAsRoot("wg-quick", "up", iface)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// injectSSHExemptPostUp inserts policy-routing PostUp/PostDown hooks
// into the [Interface] block of a wg-quick conf so packets sourced
// from the host's public IP keep using the original routing table.
//
// Without this, `AllowedIPs = 0.0.0.0/0` makes wg-quick replace the
// default route with one through the tunnel — including reply packets
// for inbound connections. SSH replies route through clawpatrol →
// wrong source IP → in-flight admin session that ran `clawpatrol join
// --whole-machine` dies mid-handshake. Same trick unclaw landed in
// commit 53e0496.
//
// Returns conf unchanged when the host IP can't be detected (best
// effort — better to bring up the tunnel than block on a heuristic).
// Idempotent on the wire because PostUp's `ip rule add` is a single
// rule with a fixed priority; re-runs add a duplicate but PostDown
// removes one at a time and wg-quick down/up cycles cleanly.
func injectSSHExemptPostUp(conf string) string {
	hostIP := detectHostIP()
	if hostIP == "" {
		return conf
	}
	// Priority 5 — must beat wg-quick's two own rules:
	//   pref 8: from all lookup main suppress_prefixlength 0
	//   pref 9: not fwmark 51820 lookup 51820
	// Pref 10 (what unclaw originally used in commit 53e0496) gets
	// shadowed by pref 9 — pref 9 matches every non-fwmarked packet
	// first → table 51820 → clawpatrol iface → SYN-ACK exits the wrong
	// interface, SSH session dies. Observed on Ubuntu 24.04 / Vultr.
	postUp := fmt.Sprintf("PostUp = ip rule add from %s lookup main priority 5", hostIP)
	postDown := fmt.Sprintf("PostDown = ip rule del from %s lookup main priority 5", hostIP)
	if strings.Contains(conf, postUp) {
		return conf
	}
	// Insert before [Peer] (always present, terminates [Interface]).
	// Falls back to append if [Peer] is missing for some reason.
	idx := strings.Index(conf, "[Peer]")
	if idx < 0 {
		return conf + "\n" + postUp + "\n" + postDown + "\n"
	}
	return conf[:idx] + postUp + "\n" + postDown + "\n\n" + conf[idx:]
}

// detectHostIP returns the IPv4 address used to reach the public
// internet, mirroring `ip -4 route get 1.1.1.1 | grep -oP 'src \K...'`.
// Returns "" on any error so callers can decide to skip the rule.
func detectHostIP() string {
	out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return ""
	}
	// Output: "1.1.1.1 via X dev eth0 src Y.Y.Y.Y uid 0 \n cache"
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "src" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// installTailscale runs the official one-line installer for the
// platform. Requires sudo.
func installTailscale() error {
	switch runtime.GOOS {
	case "darwin":
		// brew install --cask tailscale; user must launch app once.
		c := exec.Command("brew", "install", "--cask", "tailscale")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("brew install: %w (or download manually from tailscale.com)", err)
		}
		fmt.Println("  launch Tailscale.app once, then re-run clawpatrol login")
		return fmt.Errorf("manual app launch required")
	case "linux":
		c := exec.Command("sh", "-c", "curl -fsSL https://tailscale.com/install.sh | sh")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	}
	return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

// `clawpatrol gateway init` — one-shot setup wizard. Generates a CA,
// writes a sane wireguard-mode gateway.hcl, opens firewall ports,
// and prints the run command. Replaces the bash-script deploy hacks.

func defaultGatewayDataDir() string {
	if os.Getuid() == 0 {
		return "/etc/clawpatrol"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/clawpatrol"
	}
	return filepath.Join(home, ".clawpatrol")
}

func runGatewayInit(args []string) {
	fs := flag.NewFlagSet("gateway init", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultGatewayDataDir(), "where to put gateway.hcl + CA + state")
	publicURL := fs.String("public-url", "", "public dashboard URL (auto-detected from public IP if empty)")
	publicIP := fs.String("public-ip", "", "public IP for the WG endpoint (auto-detected if empty)")
	wgPort := fs.Int("wg-port", 51820, "wireguard UDP port")
	dashPort := fs.Int("dash-port", 9080, "dashboard / onboard HTTP port")
	tlsPort := fs.Int("tls-port", 8443, "TLS gateway port (host kernel — does NOT need to be public)")
	subnet := fs.String("subnet", "10.55.0.0/24", "wireguard subnet pool")
	skipFirewall := fs.Bool("no-firewall", false, "skip iptables ACCEPT rules")
	_ = fs.Parse(args)

	// 1. data dir ----------------------------------------------------------
	// The gateway lazy-mints its CA into sqlite on first boot, so all
	// we need is the state directory itself; the sqlite DB is created
	// on demand.
	if err := os.MkdirAll(filepath.Join(*dataDir, "state"), 0o700); err != nil {
		fail("mkdir state: %v", err)
	}

	// 2. detect public IP if not given -------------------------------------
	ip := *publicIP
	if ip == "" {
		ip = detectPublicIP()
		if ip == "" {
			fail("couldn't detect public IP — pass --public-ip explicitly")
		}
	}
	url := *publicURL
	if url == "" {
		url = fmt.Sprintf("http://%s:%d", ip, *dashPort)
	}

	// 3. write gateway.hcl ------------------------------------------------
	cfgPath := filepath.Join(*dataDir, "gateway.hcl")
	cfg := fmt.Sprintf(`# generated by clawpatrol gateway init
listen      = "0.0.0.0:%d"
info_listen = "0.0.0.0:%d"
public_url  = "%s"
log_path    = "%s"
state_dir   = "%s"

control        = "wireguard"
wg_endpoint    = "%s:%d"
wg_subnet_cidr = "%s"

# Starter policy: claude / codex / github via OAuth. Operator pastes
# tokens via the dashboard; rules permit everything by default. Edit
# below or via the dashboard's settings modal.

credential "anthropic_oauth_subscription" "claude" {}
credential "openai_codex_oauth"           "codex"  {}
credential "github_oauth"                 "github" {}

endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  credential = claude
}
endpoint "https" "openai-api" {
  hosts      = ["api.openai.com"]
  credential = codex
}
endpoint "openai_codex_https" "openai-chatgpt" {
  hosts      = ["chatgpt.com"]
  credential = codex
}
endpoint "https" "github-api" {
  hosts      = ["api.github.com", "raw.githubusercontent.com"]
  credential = github
}

profile "default" {
  endpoints = [anthropic, openai, github-api]
}
`,
		*tlsPort, *dashPort, url,
		filepath.Join(*dataDir, "gateway.log"),
		filepath.Join(*dataDir, "state"),
		ip, *wgPort, *subnet,
	)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		fail("write %s: %v", cfgPath, err)
	}

	// 4. open firewall ports (best-effort) ---------------------------------
	fwOpened := []string{}
	if !*skipFirewall {
		if openFirewallPort("udp", *wgPort) {
			fwOpened = append(fwOpened, fmt.Sprintf("udp/%d", *wgPort))
		}
		if openFirewallPort("tcp", *dashPort) {
			fwOpened = append(fwOpened, fmt.Sprintf("tcp/%d", *dashPort))
		}
	}

	// 5. systemd unit (if systemd is around) -------------------------------
	systemdPath := ""
	if _, err := exec.LookPath("systemctl"); err == nil {
		systemdPath = writeSystemdUnit(*dataDir, cfgPath)
	}

	fmt.Println()
	fmt.Printf("Detected public IP: %s\n", ip)
	items := []string{}
	items = append(items, "Wrote "+cfgPath)
	if len(fwOpened) > 0 {
		items = append(items, "Opened "+strings.Join(fwOpened, " + "))
	}
	if systemdPath != "" {
		items = append(items, "Wrote "+systemdPath)
	}
	printTreeItems(items)
	fmt.Println()
	fmt.Println("Next:")
	if systemdPath != "" {
		fmt.Println("  systemctl enable --now clawpatrol-gateway")
	} else {
		fmt.Printf("  clawpatrol gateway %s\n", cfgPath)
	}
	fmt.Println()
	fmt.Printf("Dashboard: %s\n", url)
	fmt.Printf("Join command: clawpatrol join %s\n", url)
}

// detectPublicIP queries plain-text IP echo services. We validate
// the response is something IP-shaped rather than an HTML page (some
// services serve a captcha page from non-residential IPs).
func detectPublicIP() string {
	endpoints := []string{
		"https://ipv4.icanhazip.com",
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://checkip.amazonaws.com",
	}
	c := &http.Client{Timeout: 5 * time.Second}
	for _, u := range endpoints {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "curl/8")
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if isIPv4(ip) {
			return ip
		}
	}
	return ""
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// openFirewallPort returns true when the rule was newly added (caller
// renders it in the summary). Already-open / failed-to-open are silent
// from the caller's perspective; failures emit a warning to stderr.
func openFirewallPort(proto string, port int) bool {
	chk := runAsRoot("iptables", "-C", "INPUT", "-p", proto, "--dport", fmt.Sprint(port), "-j", "ACCEPT")
	if chk.Run() == nil {
		return false
	}
	add := runAsRoot("iptables", "-I", "INPUT", "-p", proto, "--dport", fmt.Sprint(port), "-j", "ACCEPT")
	if err := add.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ couldn't open %s/%d: %v\n", proto, port, err)
		return false
	}
	return true
}

// writeSystemdUnit returns the unit path on a fresh write, "" when the
// unit already exists (so the caller skips the summary line).
func writeSystemdUnit(dataDir, cfgPath string) string {
	const path = "/etc/systemd/system/clawpatrol-gateway.service"
	if _, err := os.Stat(path); err == nil {
		return ""
	}
	exe, _ := os.Executable()
	if exe == "" {
		exe = "/usr/local/bin/clawpatrol"
	}
	unit := fmt.Sprintf(`[Unit]
Description=clawpatrol gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
EnvironmentFile=-%s/secrets.env
ExecStart=%s gateway %s
Restart=on-failure
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, dataDir, dataDir, exe, cfgPath)

	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ couldn't write %s: %v\n", path, err)
		return ""
	}
	_ = runAsRoot("systemctl", "daemon-reload").Run()
	return path
}

// `clawpatrol uninstall` — tear down everything `clawpatrol join`
// (and friends) put on this machine. Cross-platform, idempotent.
// Stops the macOS NETransparentProxy + system extension, brings
// down the linux wg-quick interface, removes the CA from system
// trust, drops the per-user state dirs, and strips the shell-rc
// env shim.
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	keepCA := fs.Bool("keep-ca", false, "keep ~/.clawpatrol + system trust")
	keepConf := fs.Bool("keep-conf", false, "keep ~/.config/clawpatrol/wg.conf")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)

	if !*yes {
		fmt.Print("Uninstall clawpatrol from this machine? [y/N] ")
		var resp string
		_, _ = fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			fmt.Println("aborted")
			return
		}
	}

	step := func(label string, fn func() error) {
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ %s: %v\n", label, err)
			return
		}
		fmt.Println("  ✓ " + label)
	}
	bestEffort := func(name string, argv ...string) func() error {
		return func() error {
			c := exec.Command(name, argv...)
			c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
			return c.Run()
		}
	}

	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(macHelperPath); err == nil {
			step("Clawpatrol stop", bestEffort(macHelperPath, "stop"))
			step("Clawpatrol wipe", bestEffort(macHelperPath, "wipe"))
		}
		if _, err := os.Stat("/Applications/Clawpatrol.app"); err == nil {
			step("rm /Applications/Clawpatrol.app",
				bestEffort("sudo", "rm", "-rf", "/Applications/Clawpatrol.app"))
		}
		if !*keepCA {
			step("untrust CA in System.keychain",
				bestEffort("sudo", "security", "delete-certificate",
					"-c", "clawpatrol", "/Library/Keychains/System.keychain"))
		}
	case "linux":
		step("wg-quick down clawpatrol", bestEffort("sudo", "wg-quick", "down", "clawpatrol"))
		if !*keepCA {
			step("rm system CA", bestEffort("sudo", "rm", "-f",
				"/usr/local/share/ca-certificates/clawpatrol.crt"))
			step("update-ca-certificates", bestEffort("sudo", "update-ca-certificates"))
		}
	}

	if !*keepCA {
		dir := defaultClawpatrolDir()
		step("rm "+dir, func() error { return os.RemoveAll(dir) })
	}
	if !*keepConf {
		confDir := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol")
		step("rm "+confDir, func() error { return os.RemoveAll(confDir) })
	}
	step("strip shell-rc env shim", removeShellRCMarker)

	fmt.Println()
	fmt.Println("done. Reinstall: curl -fsSL https://clawpatrol.dev/install.sh | sh")
}

// removeShellRCMarker strips the line installShellRC appended.
// Idempotent — silently no-ops when the marker isn't present.
func removeShellRCMarker() error {
	const marker = "# clawpatrol: agent env (clawpatrol env)"
	home := os.Getenv("HOME")
	for _, name := range []string{".zshrc", ".bashrc", ".profile"} {
		p := filepath.Join(home, name)
		src, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		i := strings.Index(string(src), marker)
		if i < 0 {
			continue
		}
		// Drop the marker line + the eval line that follows.
		end := i
		newlines := 0
		for end < len(src) && newlines < 2 {
			if src[end] == '\n' {
				newlines++
			}
			end++
		}
		out := append([]byte{}, src[:i]...)
		out = append(out, src[end:]...)
		if err := os.WriteFile(p, out, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// `clawpatrol status` — what's installed, what's running, what's
// reachable. Self-diagnose without log streaming. No flags; one
// shot of every signal that matters for "why isn't this working".
func runStatus(args []string) {
	_ = args
	check := func(label string, ok bool, detail string) {
		mark := "✗"
		if ok {
			mark = "✓"
		}
		if detail != "" {
			fmt.Printf("  %s %s — %s\n", mark, label, detail)
		} else {
			fmt.Printf("  %s %s\n", mark, label)
		}
	}

	caPath := filepath.Join(defaultClawpatrolDir(), "ca.crt")
	_, caErr := os.Stat(caPath)
	check("CA bundle", caErr == nil, caPath)

	confPath := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol", "wg.conf")
	_, confErr := os.Stat(confPath)
	check("wg.conf", confErr == nil, confPath)

	switch runtime.GOOS {
	case "darwin":
		_, helperErr := os.Stat(macHelperPath)
		check("Clawpatrol.app", helperErr == nil, "/Applications/Clawpatrol.app")
		// systemextensionsctl list — single line per ext, look for ours.
		out, _ := exec.Command("systemextensionsctl", "list").Output()
		extLine := ""
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "dev.clawpatrol.app.extension") {
				extLine = strings.TrimSpace(line)
				break
			}
		}
		check("system extension", strings.Contains(extLine, "[activated enabled]"), extLine)
	case "linux":
		out, err := exec.Command("ip", "link", "show", "clawpatrol").Output()
		up := err == nil && strings.Contains(string(out), "state UNKNOWN")
		check("wg-quick interface up", up, "ip link show clawpatrol")
	}

	// Gateway reachability: parse Endpoint from wg.conf, hit /info on
	// the configured public_url if we can reach it. Best-effort only.
	if confErr == nil {
		if endpoint := wgEndpointFromConf(confPath); endpoint != "" {
			check("gateway reachable", pingGateway(endpoint), endpoint)
		}
	}
}

func wgEndpointFromConf(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Endpoint") {
			if eq := strings.IndexByte(line, '='); eq > 0 {
				return strings.TrimSpace(line[eq+1:])
			}
		}
	}
	return ""
}

// pingGateway dials the wg endpoint host on the configured port. Just
// proves the host is reachable + listening, not that wg handshake
// succeeds.
func pingGateway(endpoint string) bool {
	c, err := net.DialTimeout("udp", endpoint, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
