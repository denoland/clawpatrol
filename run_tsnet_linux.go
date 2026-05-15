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
	"os"

	tstun "github.com/tailscale/wireguard-go/tun"
	"tailscale.com/tsnet"
)

type tsnetRunOpts struct {
	controlURL string
	hostname   string
	exitNode   string // hostname or IP of the gateway exit node
	stateDir   string // populated by `clawpatrol join`; carries node identity
}

// runTsnetParent brings up the embedded tsnet node bound to tunFd
// (handed up from the namespaced child), points it at the operator's
// gateway as an exit node, and returns the netns-side address line
// (`v4/32, v6/128`) the child must `ip addr add` plus a cleanup that
// tears tsnet down. Node identity comes from opts.stateDir, which
// `clawpatrol join` seeded with the one-shot authkey — no authkey is
// needed at run time.
func runTsnetParent(ctx context.Context, tunFd int, opts tsnetRunOpts, logger *log.Logger) (addrLine string, cleanup func(), err error) {
	if opts.exitNode == "" {
		return "", nil, errors.New("tsnet: empty exit-node (run `clawpatrol join --tsnet-authkey ... --tsnet-exit-node ...`)")
	}
	if opts.stateDir == "" {
		return "", nil, errors.New("tsnet: empty state dir")
	}
	if _, err := os.Stat(opts.stateDir); err != nil {
		return "", nil, fmt.Errorf("tsnet state dir %s: %w (run `clawpatrol join --tsnet-authkey ... --tsnet-exit-node ...` first)", opts.stateDir, err)
	}

	tunDev := newTsnetFDTun(tunFd)
	srv := &tsnet.Server{
		Hostname:   opts.hostname,
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
