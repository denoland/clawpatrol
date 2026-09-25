package main

// Liveness self-heal for an enrolled bridge peer's WireGuard tunnel.
//
// This is deliberately separate from wg_watchdog.go, which preserves the
// upstream handshake-state-machine recovery path. The bridge watchdog reasons
// about an enrolled peer's rx/probe/re-enrollment lifecycle instead.
//
// The sidecar is the sole (authoritative) keepalive sender — the gateway does
// not keepalive back (see registerEnrolledPeer) — so the sidecar's own
// rx_bytes is normally quiet on an idle tunnel. The watchdog therefore uses
// rx_bytes only as a cheap positive signal: while it advances, inbound works
// and nothing is done. When it goes quiet, the watchdog actively probes the
// gateway's tunnel address with an ICMP echo to disambiguate "healthy but
// idle" from "actually broken" — a round-trip reply proves both directions.
//
// When no ICMP socket can be opened (errProbeUnavailable), the watchdog uses
// the age of the last WireGuard handshake instead. The bridge sends
// keepalives, so a healthy tunnel re-handshakes at least every
// RejectAfterTime. This detects a dead tunnel more slowly than the probe.
//
// On sustained probe failure it escalates:
//
//   - at rekeyAfterFails consecutive failures: rebuild the peer in place
//     (IpcSet). Cheap; clears a transient local wedge.
//   - at reconnectAfterFails consecutive failures: trigger a full in-process
//     teardown + re-enroll (reconnect), then return so a fresh watchdog runs
//     with the new session.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

const (
	// bridgeWatchdogPoll is how often the loop samples rx_bytes. Small so the
	// watchdog reacts promptly when real inbound traffic resumes.
	bridgeWatchdogPoll = 5 * time.Second
	// bridgeWatchdogDefaultResetMisses is the default for
	// --local-reset-missed: how many consecutive failed probes trigger the
	// cheap in-place rekey before the full reconnect. Clamped below the
	// reconnect threshold.
	bridgeWatchdogDefaultResetMisses = 2
)

const (
	// bridgeTunnelReadyTimeout bounds how long bring-up waits for the first
	// handshake and probe reply. Bring-up retries after it, and the example
	// startup probe allows 120s.
	bridgeTunnelReadyTimeout = 20 * time.Second
	bridgeTunnelReadyPoll    = 200 * time.Millisecond
)

// errProbeUnavailable means the bridge cannot send ICMP probes (no
// ping_group_range for its GID and no CAP_NET_RAW). It is not a liveness
// failure.
var errProbeUnavailable = errors.New("icmp probe unavailable")

// bridgeHandshakeStaleAfter is the handshake age that counts as a failed
// check when the probe is unavailable. wireguard-go starts a new handshake on
// send once the key is RejectAfterTime (180s) old; allow one keepalive
// interval for that send and RekeyAttemptTime (90s) of retries.
func bridgeHandshakeStaleAfter(keepalive time.Duration) time.Duration {
	return 180*time.Second + keepalive + 90*time.Second
}

// bridgeWatchdogConfig captures the runBridgeWatchdogLoop dependencies so the
// loop is testable without a real wireguard-go device or a real network.
type bridgeWatchdogConfig struct {
	// rx returns the peer's current WireGuard rx_bytes (0 if unavailable).
	rx func() uint64
	// probe sends one liveness probe (ICMP echo to the gateway tunnel IP) and
	// returns nil on a reply, an error on failure/timeout. nil, or a probe that
	// returns errProbeUnavailable, selects the handshake-age fallback.
	probe func() error
	// lastHandshake returns the peer's last WireGuard handshake time (zero if
	// none). handshakeStaleAfter is the fallback threshold.
	lastHandshake       func() time.Time
	handshakeStaleAfter time.Duration
	// rekey rebuilds the peer in place (IpcSet) — the cheap first escalation.
	rekey func() error
	// reconnect triggers a full in-process teardown + re-enroll. After it is
	// called the loop returns; a fresh watchdog starts with the new session.
	reconnect func()
	logf      func(string, ...any)
	tick      <-chan time.Time
	now       func() time.Time
	// probeAfter is how long rx must be quiet before the first probe;
	// probeInterval rate-limits probes once quiet. Both are the keepalive
	// interval in practice.
	probeAfter    time.Duration
	probeInterval time.Duration
	// rekeyAfterFails / reconnectAfterFails are consecutive-probe-failure
	// counts. rekeyAfterFails == 0 disables the in-place rekey stage;
	// reconnectAfterFails <= 0 leaves the whole loop inert (reaping disabled).
	rekeyAfterFails     int
	reconnectAfterFails int
}

// bridgeWatchdogResetMisses resolves the configured local-reset threshold
// against the reconnect horizon: 0 (or a value >= the horizon) disables the
// in-place rekey stage, otherwise the configured value is used.
func bridgeWatchdogResetMisses(configured, reconnectAfter int) int {
	if configured <= 0 || configured >= reconnectAfter {
		return 0
	}
	return configured
}

func runBridgeWatchdogLoop(ctx context.Context, c bridgeWatchdogConfig) {
	logf := c.logf
	if logf == nil {
		logf = log.Printf
	}
	// Inert when reaping is disabled server-side: nothing to escalate to.
	if c.reconnectAfterFails <= 0 {
		return
	}
	var (
		tracking       bool
		lastRx         uint64
		lastLive       time.Time
		lastProbe      time.Time
		fails          int
		rekeyed        bool
		rekeys         int
		fallbackLogged bool
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.tick:
		}
		now := c.now()
		rx := c.rx()
		if !tracking {
			tracking, lastRx, lastLive = true, rx, now
			continue
		}
		if rx > lastRx {
			// Positive inbound signal — the tunnel is healthy, no probe needed.
			if fails > 0 || rekeyed {
				logf("bridge watchdog: WG rx resumed — tunnel healthy again")
			}
			lastRx, lastLive, fails, rekeyed = rx, now, 0, false
			continue
		}
		// rx is quiet. Act only once it has been quiet long enough, and
		// rate-limit the probe to the probe interval.
		if now.Sub(lastLive) < c.probeAfter {
			continue
		}
		if !lastProbe.IsZero() && now.Sub(lastProbe) < c.probeInterval {
			continue
		}

		lastProbe = now
		err := errProbeUnavailable
		if c.probe != nil {
			err = c.probe()
		}
		if errors.Is(err, errProbeUnavailable) {
			if !fallbackLogged {
				logf("bridge watchdog: %v; checking WireGuard handshake age instead", err)
				fallbackLogged = true
			}
			err = c.handshakeFresh(now)
		}
		if err == nil {
			// Healthy but idle. The reply also advances rx (handled next tick),
			// but count the success as liveness now.
			if fails > 0 || rekeyed {
				logf("bridge watchdog: gateway probe recovered — tunnel healthy again")
			}
			lastRx, lastLive, fails, rekeyed = c.rx(), now, 0, false
			continue
		}
		fails++
		logf("bridge watchdog: gateway liveness probe failed (%d/%d): %v", fails, c.reconnectAfterFails, err)

		if fails >= c.reconnectAfterFails {
			logf("bridge watchdog: %d consecutive probe failures — tearing down and reconnecting in-process", fails)
			if c.reconnect != nil {
				c.reconnect()
			}
			return
		}
		if c.rekeyAfterFails > 0 && fails >= c.rekeyAfterFails && !rekeyed {
			rekeys++
			logf("bridge watchdog: %d consecutive probe failures — rebuilding peer in place (rekey #%d)", fails, rekeys)
			if err := c.rekey(); err != nil {
				logf("bridge watchdog: peer rekey failed: %v", err)
			} else {
				rekeyed = true
			}
		}
	}
}

// handshakeFresh is the liveness check used when the probe is unavailable.
func (c bridgeWatchdogConfig) handshakeFresh(now time.Time) error {
	if c.lastHandshake == nil || c.handshakeStaleAfter <= 0 {
		return nil
	}
	hs := c.lastHandshake()
	if hs.IsZero() {
		return fmt.Errorf("no WireGuard handshake yet")
	}
	if age := now.Sub(hs); age > c.handshakeStaleAfter {
		return fmt.Errorf("last WireGuard handshake %s ago (> %s)", age.Round(time.Second), c.handshakeStaleAfter)
	}
	return nil
}

// waitForTunnel returns once the tunnel carries traffic: a WireGuard handshake
// has completed and, when probe is set, one probe got a reply. An unavailable
// probe counts as a reply, because the handshake already proved the path.
func waitForTunnel(ctx context.Context, lastHandshake func() time.Time, probe func() error, poll, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for lastHandshake().IsZero() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("no WireGuard handshake within %s", timeout)
		case <-ticker.C:
		}
	}
	if probe == nil {
		return nil
	}
	for {
		err := probe()
		if err == nil || errors.Is(err, errProbeUnavailable) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no reply from the gateway tunnel address within %s: %w", timeout, err)
		case <-ticker.C:
		}
	}
}
