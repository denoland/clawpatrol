//go:build linux

package main

// tsnet path for `clawpatrol run`. Mirrors the WG path's plumbing —
// child opens TUN inside an unprivileged netns, parent owns the TUN
// fd and drives the network stack — but swaps wireguard-go for an
// embedded `tsnet.Server` that joins a tailnet via a literal authkey
// and uses the operator-supplied gateway as its `ExitNodeIP` /
// `ExitNodeID`. The tsnet stack writes inbound packets to the TUN
// (visible inside the netns) and reads outbound packets from it,
// encrypts them with wgengine, and ships them out over the parent's
// host-netns UDP socket.
//
// Selection: `--tsnet-authkey` (or `CLAWPATROL_RUN_TSNET_AUTHKEY`) is
// the trigger. When set, the WG `wg.conf` / ephemeral-peer code path
// is skipped entirely; otherwise behaviour is unchanged.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	tstun "github.com/tailscale/wireguard-go/tun"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type tsnetRunOpts struct {
	authKey    string
	controlURL string
	hostname   string
	exitNode   string // hostname or IP of the gateway exit node
	stateDir   string
}

// runTsnetParent brings up the embedded tsnet node bound to tunFd
// (handed up from the namespaced child), points it at the operator's
// gateway as an exit node, and returns the netns-side address line
// (`v4/32, v6/128`) the child must `ip addr add` plus a cleanup that
// tears tsnet down.
func runTsnetParent(ctx context.Context, tunFd int, opts tsnetRunOpts, logger *log.Logger) (addrLine string, cleanup func(), err error) {
	if opts.authKey == "" {
		return "", nil, errors.New("tsnet: empty authkey")
	}
	if opts.exitNode == "" {
		return "", nil, errors.New("tsnet: --tsnet-exit-node is required (gateway hostname or tailnet IP)")
	}
	if opts.stateDir == "" {
		return "", nil, errors.New("tsnet: empty state dir")
	}
	if err := os.MkdirAll(opts.stateDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("tsnet state dir: %w", err)
	}

	tunDev := newTsnetFDTun(tunFd)
	srv := &tsnet.Server{
		Hostname:   opts.hostname,
		AuthKey:    opts.authKey,
		ControlURL: opts.controlURL,
		Dir:        opts.stateDir,
		Tun:        tunDev,
		Logf:       func(f string, args ...any) { logger.Printf(f, args...) },
	}

	closer := func() {
		_ = srv.Close()
	}

	status, err := srv.Up(ctx)
	if err != nil {
		closer()
		return "", nil, fmt.Errorf("tsnet up: %w", err)
	}
	if len(status.TailscaleIPs) == 0 {
		closer()
		return "", nil, errors.New("tsnet: no tailnet IP after Up")
	}

	mp, err := exitNodePrefs(status, opts.exitNode)
	if err != nil {
		closer()
		return "", nil, err
	}
	lc, err := srv.LocalClient()
	if err != nil {
		closer()
		return "", nil, fmt.Errorf("tsnet local client: %w", err)
	}
	if _, err := lc.EditPrefs(ctx, mp); err != nil {
		closer()
		return "", nil, fmt.Errorf("tsnet edit prefs (exit node): %w", err)
	}

	var parts []string
	for _, ip := range status.TailscaleIPs {
		if ip.Is4() {
			parts = append(parts, ip.String()+"/32")
		} else {
			parts = append(parts, ip.String()+"/128")
		}
	}
	addrLine = joinAddrs(parts)
	logger.Printf("tsnet: joined as %q (%s); exit-node=%s", srv.Hostname, addrLine, opts.exitNode)
	return addrLine, closer, nil
}

// exitNodePrefs resolves the operator's --tsnet-exit-node value to an
// IP and packages it as a MaskedPrefs. IP literals go straight in;
// anything else is matched (case-insensitively) against peer Hostname
// / DNSName. We surface a clear error when the gateway isn't visible
// yet so the operator hits a real failure ("no peer matched") rather
// than silently routing in the clear.
func exitNodePrefs(status *ipnstate.Status, exitNode string) (*ipn.MaskedPrefs, error) {
	if ip, err := netip.ParseAddr(exitNode); err == nil {
		return &ipn.MaskedPrefs{
			ExitNodeIPSet: true,
			Prefs:         ipn.Prefs{ExitNodeIP: ip},
		}, nil
	}
	want := strings.ToLower(strings.TrimSuffix(exitNode, "."))
	for _, p := range status.Peer {
		if p == nil {
			continue
		}
		dns := strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
		host := strings.ToLower(p.HostName)
		// MagicDNS DNSNames look like "host.tail-xxxx.ts.net"; an
		// operator supplying just "host" should still match.
		if want == host || want == dns || strings.HasPrefix(dns, want+".") {
			if len(p.TailscaleIPs) == 0 {
				return nil, fmt.Errorf("tsnet exit-node %q matched peer but it has no tailnet IP yet", exitNode)
			}
			return &ipn.MaskedPrefs{
				ExitNodeIPSet: true,
				Prefs:         ipn.Prefs{ExitNodeIP: p.TailscaleIPs[0]},
			}, nil
		}
	}
	return nil, fmt.Errorf("tsnet exit-node %q: no peer matched (peer must be online and visible to this tailnet)", exitNode)
}

func joinAddrs(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		out := parts[0]
		for _, p := range parts[1:] {
			out += ", " + p
		}
		return out
	}
}

// defaultTsnetStateDir places per-run tsnet state under the user's
// clawpatrol dir so credentials persist across `clawpatrol run`
// invocations and the second run is a fast warm-cache join.
func defaultTsnetStateDir() string {
	return filepath.Join(defaultClawpatrolDir(), "run-tsnet")
}

// --- TUN adapter for tailscale's wireguard-go fork ----------------

// tsnetFDTun mirrors rawFDTun (zx2c4 fork) but satisfies the tailscale
// fork's tun.Device interface. tsnet imports
// github.com/tailscale/wireguard-go/tun, whose Event type is distinct
// from zx2c4's despite being structurally identical, so the adapter
// has to be duplicated even though the read/write halves are byte-
// identical.
type tsnetFDTun struct {
	f      *os.File
	events chan tstun.Event
}

func newTsnetFDTun(fd int) *tsnetFDTun {
	t := &tsnetFDTun{
		f:      os.NewFile(uintptr(fd), tunIfName),
		events: make(chan tstun.Event, 1),
	}
	t.events <- tstun.EventUp
	return t
}

func (t *tsnetFDTun) File() *os.File             { return t.f }
func (t *tsnetFDTun) Name() (string, error)      { return tunIfName, nil }
func (t *tsnetFDTun) MTU() (int, error)          { return tunMTU, nil }
func (t *tsnetFDTun) Events() <-chan tstun.Event { return t.events }
func (t *tsnetFDTun) BatchSize() int             { return 1 }
func (t *tsnetFDTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.f.Read(bufs[0][offset:])
	if n > 0 {
		sizes[0] = n
	}
	return 1, err
}
func (t *tsnetFDTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if _, err := t.f.Write(b[offset:]); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}
func (t *tsnetFDTun) Close() error {
	close(t.events)
	return t.f.Close()
}
