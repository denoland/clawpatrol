package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	gatewayURL := fs.String("url", "", "gateway URL (e.g. http://gw.example.com:8080) — required")
	gwName := fs.String("name", "clawpatrol", "exit-node hostname on the tailnet")
	caOut := fs.String("ca-dir", defaultClawpatrolDir(), "where to store the fetched CA")
	skipTrust := fs.Bool("no-trust", false, "fetch CA but skip system trust install (do it manually)")
	_ = fs.Parse(args)
	if *gatewayURL == "" {
		fail("usage: clawpatrol join --url <gateway-url>")
	}
	// Fetch CA + write shell rc BEFORE the VPN goes up. Once
	// `wg-quick up` flips the default route through the gateway,
	// reaching the gateway's public URL goes via the tunnel — which
	// can't carry traffic until the gateway has internet egress
	// configured (MASQUERADE etc). The CA is small + cheap and the
	// onboard endpoints are reachable on the public path.
	if err := postJoinSetup(*gatewayURL, *caOut, *skipTrust); err != nil {
		fail("ca fetch: %v", err)
	}
	wgMode, err := onboardViaDeviceFlow(*gatewayURL)
	if err != nil {
		fail("join: %v", err)
	}
	if wgMode {
		fmt.Printf("\n✓ joined via wireguard. start agents with:\n  eval \"$(clawpatrol env)\"\n  claude\n")
		return
	}
	// Tailscale-specific path: exit-node + whois identity.
	loginArgs := []string{"-name", *gwName, "-ca-dir", *caOut}
	if *skipTrust {
		loginArgs = append(loginArgs, "-no-trust")
	}
	runLogin(loginArgs)
}

// postJoinSetup downloads the gateway's CA, installs it into the
// system trust store (best-effort), and appends the env shim to the
// shell rc. Used by both wireguard and tailscale onboarding paths.
func postJoinSetup(gateway, caDir string, skipTrust bool) error {
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", caDir, err)
	}
	caPath := filepath.Join(caDir, "ca.crt")
	if err := fetchCAHTTP(gateway, caPath); err != nil {
		return fmt.Errorf("fetch CA: %w", err)
	}
	if !skipTrust {
		if err := installCATrust(caPath); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ couldn't install CA into system trust: %v\n  trust manually:\n  %s\n", err, manualTrustHint(caPath))
		} else {
			fmt.Println("✓ ca installed in system trust")
		}
	}
	if err := installShellRC(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ shell rc append failed: %v\n", err)
	}
	return nil
}

func fetchCAHTTP(gateway, dst string) error {
	url := strings.TrimRight(gateway, "/") + "/ca.crt"
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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
	if !*skipExitNode && runtime.GOOS == "linux" {
		if err := exemptSSHFromExitNode(""); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ couldn't protect SSH (will skip exit-node): %v\n", err)
			*skipExitNode = true
		} else {
			fmt.Println("⎿ SSH (tcp/22) reply traffic pinned to direct route")
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
	fmt.Printf("\nConnected to %s's tailnet.\n", tailnetName)

	peer := findPeerByName(st, *gwName)
	if peer == nil {
		fail("no peer named %q on this tailnet — is the gateway running and joined?", *gwName)
	}
	fmt.Printf("⎿ Found exit node: %s (%s)\n", *gwName, peer.TailscaleIPs[0])

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

	if *skipTrust {
		fmt.Printf("\n⚠ CA install skipped. trust manually:\n  %s\n", manualTrustHint(caPath))
		return
	}
	if err := installCATrust(caPath); err != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ could not install CA into system trust: %v\n", err)
		fmt.Fprintf(os.Stderr, "trust manually:\n  %s\n", manualTrustHint(caPath))
		return
	}
	if err := installShellRC(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ couldn't auto-source clawpatrol env in shell rc: %v\n", err)
		fmt.Printf("\nadd to your shell rc manually:\n  eval \"$(clawpatrol env)\"\n")
	} else {
		fmt.Printf("\n✓ added `eval \"$(clawpatrol env)\"` to your shell rc — start a new shell\n")
	}
	fmt.Printf("\nthen just run:\n  claude\n  gh\n")
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
			f.Close()
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
	defer resp.Body.Close()
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

// onboardViaDeviceFlow: brand-new client (no tailscale yet) calls the
// gateway dashboard, gets a user_code, prompts the user to approve on
// an existing trusted device, polls for the minted Tailscale auth key,
// installs Tailscale (if missing), and runs `tailscale up --authkey`.
// onboardViaDeviceFlow drives the device-flow handshake against the
// gateway and ends in a working VPN connection. Returns wgMode=true
// when the gateway picked the wireguard control plane (caller skips
// tailscale-specific post-setup).
func onboardViaDeviceFlow(gateway string) (bool, error) {
	gateway = strings.TrimRight(gateway, "/")
	cli := &http.Client{Timeout: 30 * time.Second}

	// 1. start
	resp, err := cli.Post(gateway+"/api/onboard/start", "application/json", nil)
	if err != nil {
		return false, fmt.Errorf("start: %w", err)
	}
	defer resp.Body.Close()
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

	fmt.Printf("\n  open this and approve:\n\n    %s\n\n  code: %s\n\n", start.VerifyURL, start.UserCode)
	tryOpen(start.VerifyURL)

	// 2. poll
	interval := time.Duration(start.Interval) * time.Second
	if interval == 0 {
		interval = 3 * time.Second
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	authKey, loginServer := "", ""
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		pr, err := cli.Post(gateway+"/api/onboard/poll?device_code="+start.DeviceCode, "application/json", nil)
		if err != nil {
			continue
		}
		var pv map[string]string
		_ = json.NewDecoder(pr.Body).Decode(&pv)
		pr.Body.Close()
		if k, ok := pv["auth_key"]; ok && k != "" {
			authKey = k
			loginServer = pv["login_server"]
			break
		}
		if e := pv["error"]; e != "" && e != "authorization_pending" && e != "slow_down" {
			return false, fmt.Errorf("poll: %s (%s)", e, pv["detail"])
		}
		fmt.Print(".")
	}
	if authKey == "" {
		return false, fmt.Errorf("timed out waiting for approval")
	}
	fmt.Println("\n✓ approved")

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
		if err := wgQuickUp(iface, authKey); err != nil {
			return true, fmt.Errorf("wg-quick up: %w", err)
		}
		fmt.Printf("✓ wireguard up (%s) — all traffic routed via gateway\n", iface)
		return true, nil
	}

	// 3b. tailscale branch — ensure binary + daemon.
	if _, err := tailscaleBin(); err != nil {
		fmt.Println("  installing tailscale (will require sudo)…")
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
	fmt.Println("✓ joined tailnet")

	// 5. claim — tell gateway "this tailnet IP belongs to <approver>".
	myIP, _ := exec.Command(tscli, "ip", "-4").Output()
	tailIP := strings.TrimSpace(strings.SplitN(string(myIP), "\n", 2)[0])
	if tailIP == "" {
		fmt.Fprintln(os.Stderr, "⚠ couldn't read tailnet IP — onboard claim skipped")
		return false, nil
	}
	claimURL := fmt.Sprintf("%s/api/onboard/claim?device_code=%s&ip=%s",
		gateway, start.DeviceCode, tailIP)
	cr, err := cli.Post(claimURL, "application/json", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ onboard claim failed: %v\n", err)
		return false, nil
	}
	defer cr.Body.Close()
	if cr.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(cr.Body, 400))
		fmt.Fprintf(os.Stderr, "⚠ onboard claim %d: %s\n", cr.StatusCode, string(body))
		return false, nil
	}
	fmt.Printf("✓ claimed %s for your account\n", tailIP)
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
	tmp, err := os.CreateTemp("", "clawpatrol-wg-*.conf")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(conf); err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := runAsRoot("install", "-m", "0600", tmp.Name(), dst).Run(); err != nil {
		return fmt.Errorf("install conf: %w", err)
	}
	// `wg-quick up` is idempotent enough — bring down first if up.
	_ = runAsRoot("wg-quick", "down", iface).Run()
	c := runAsRoot("wg-quick", "up", iface)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
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
