package main

// Recovery path for a stuck wireguard-go handshake state machine.
//
// What goes wrong: when a rekey races on the wire (initiation+response
// collide, or the response is dropped on the way back), the peer can
// land in `handshakeInitiationCreated` with no path out. Inside
// wireguard-go, `Peer.BeginSymmetricSession` then refuses to derive a
// keypair ("invalid state for keypair derivation: handshakeInitiationCreated")
// and the timers don't always pry the state machine back into a usable
// state. From the operator's seat: `clawpatrol run` survives one
// session lifetime (~3-4 hours), then every flow through the MITM
// proxy fails with `ConnectionRefused` and the process never recovers.
//
// What this watchdog does: poll the device's `last_handshake_time_sec`
// + `tx_bytes` via IpcGet, and when the gap exceeds RejectAfterTime
// (180s) while traffic is still being staged, rebuild the peer with
// the original IpcSet config. That wipes the handshake trie cleanly
// and forces a fresh initiation. A logger hook (forceReset) lets the
// "Failed to derive keypair" error short-circuit the poll cadence so
// recovery starts within milliseconds of the race firing.

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// wgPeerStats is the per-peer subset of IpcGet output we care about.
type wgPeerStats struct {
	lastHandshake time.Time
	txBytes       uint64
	rxBytes       uint64
}

// wgWatchdogConfig captures the runWGWatchdogLoop dependencies so the
// loop is testable without standing up a real wireguard-go device.
type wgWatchdogConfig struct {
	stats         func() *wgPeerStats
	reset         func() error
	log           *device.Logger
	forceReset    <-chan struct{}
	tick          <-chan time.Time
	stuckTimeout  time.Duration
	resetCooldown time.Duration
	now           func() time.Time
}

func runWGWatchdogLoop(ctx context.Context, c wgWatchdogConfig) {
	var (
		seenHandshake bool
		lastTx        uint64
		lastResetAt   time.Time
		forced        bool
	)
	logf := func(format string, args ...any) {
		if c.log != nil && c.log.Errorf != nil {
			c.log.Errorf(format, args...)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.tick:
		case <-c.forceReset:
			forced = true
		}

		s := c.stats()
		if s == nil {
			continue
		}
		if !s.lastHandshake.IsZero() {
			seenHandshake = true
		}
		// Don't reset before the very first handshake completes. A
		// missing initial handshake is a config/network problem, not
		// the state-machine race; rebuilding the peer won't fix it
		// and only adds noise.
		if !seenHandshake && !forced {
			lastTx = s.txBytes
			continue
		}
		if !lastResetAt.IsZero() && c.now().Sub(lastResetAt) < c.resetCooldown {
			continue
		}

		if !forced {
			age := c.now().Sub(s.lastHandshake)
			if age <= c.stuckTimeout {
				lastTx = s.txBytes
				continue
			}
			// Idle tunnels can legitimately have a stale lastHandshake
			// — nothing triggered a rekey because nothing's been sent.
			// Only act when the device is trying to push traffic.
			if s.txBytes == lastTx {
				lastTx = s.txBytes
				continue
			}
		}

		age := "n/a"
		if !s.lastHandshake.IsZero() {
			age = c.now().Sub(s.lastHandshake).Round(time.Second).String()
		}
		logf("watchdog: WG handshake stuck (last %s ago) — rebuilding peer", age)
		if err := c.reset(); err != nil {
			logf("watchdog: peer reset failed: %v", err)
			continue
		}
		lastResetAt = c.now()
		lastTx = s.txBytes
		forced = false
	}
}

// wrapWGLogger returns a device.Logger that delegates to base and
// signals forceReset whenever wireguard-go logs the keypair-derivation
// failure. The channel is buffered to one element so concurrent
// failures coalesce into a single reset request — the watchdog only
// needs the wake-up, not a per-event count.
func wrapWGLogger(base *device.Logger, forceReset chan<- struct{}) *device.Logger {
	if base == nil {
		base = &device.Logger{Errorf: device.DiscardLogf, Verbosef: device.DiscardLogf}
	}
	return &device.Logger{
		Verbosef: base.Verbosef,
		Errorf: func(format string, args ...any) {
			if base.Errorf != nil {
				base.Errorf(format, args...)
			}
			if strings.Contains(format, "Failed to derive keypair") {
				select {
				case forceReset <- struct{}{}:
				default:
				}
			}
		},
	}
}

func parsePeerStats(uapi string) *wgPeerStats {
	s := &wgPeerStats{}
	var secs, nsec int64
	sc := bufio.NewScanner(strings.NewReader(uapi))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			secs, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			x, _ := strconv.ParseUint(v, 10, 64)
			s.txBytes = x
		case "rx_bytes":
			x, _ := strconv.ParseUint(v, 10, 64)
			s.rxBytes = x
		}
	}
	if secs != 0 || nsec != 0 {
		s.lastHandshake = time.Unix(secs, nsec)
	}
	return s
}
