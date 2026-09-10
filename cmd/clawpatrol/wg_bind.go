package main

import (
	"errors"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
)

// gsoFallbackBind wraps wireguard-go's default UDP bind so a path
// narrower than the WireGuard packet size does not black-hole the
// tunnel.
//
// On Linux the default bind coalesces same-size packets into one
// sendmsg with UDP_SEGMENT (GSO). The kernel refuses a GSO segment
// larger than the route MTU with EMSGSIZE, and wireguard-go only
// turns GSO off on EIO, so over a 1280-byte path (a gateway reached
// through Tailscale, for example) every full-size batch fails
// forever: small requests work, anything past ~16 KiB stalls, and
// the log fills with "sendmmsg: message too long" (#790). A plain
// datagram over the same route is fragmented by the kernel and
// arrives fine.
//
// The wrapper sends batches as usual; the first EMSGSIZE switches
// it to one datagram per send for the life of the bind. MTU stays
// 1420, IPv6 inside the tunnel keeps working, and paths that can
// carry full batches never pay for it.
//
// One known cost: wireguard-go starts its Linux route-change
// listener (device/sticky_linux.go) only when the bind is the
// concrete *conn.StdNetBind, so wrapping it loses that listener.
// Its job is to drop a peer's cached source address when the route
// to it changes; without it the address is still refreshed by every
// received packet and by the handshake-retry timers, so after an
// interface change a silent peer can see stale-source sends for a
// few seconds instead of none. The proper fix is upstream (treat
// EMSGSIZE like EIO in conn/errors_linux.go); until then this is the
// smaller trade.
//
// Only Linux coalesces with GSO, so other platforms get the plain
// bind.
type gsoFallbackBind struct {
	conn.Bind
	single   atomic.Bool
	logOnce  sync.Once
	describe string
}

func newGSOFallbackBind(describe string) conn.Bind {
	b := conn.NewDefaultBind()
	if runtime.GOOS != "linux" {
		return b
	}
	return &gsoFallbackBind{Bind: b, describe: describe}
}

func (b *gsoFallbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if len(bufs) <= 1 || b.single.Load() {
		return b.sendEach(bufs, ep)
	}
	err := b.Bind.Send(bufs, ep)
	if err == nil || !errors.Is(err, syscall.EMSGSIZE) {
		return err
	}
	b.single.Store(true)
	b.logOnce.Do(func() {
		log.Printf("%s: path MTU is smaller than a batched WireGuard packet; sending one datagram per syscall from now on", b.describe)
	})
	return b.sendEach(bufs, ep)
}

// sendEach sends every buffer as its own datagram. A single-buffer
// Send never carries a GSO header (bind_std.go coalesceMessages only
// sets one when it merged two or more datagrams), so the kernel
// fragments it when the route is narrower than the packet. When a
// batch failed part-way, the datagrams the kernel already accepted
// are sent again; WireGuard's receiver drops them as replays.
func (b *gsoFallbackBind) sendEach(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if err := b.Bind.Send([][]byte{buf}, ep); err != nil {
			return err
		}
	}
	return nil
}
